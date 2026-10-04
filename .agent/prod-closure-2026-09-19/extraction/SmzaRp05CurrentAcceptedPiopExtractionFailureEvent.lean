import SmzaRp05CurrentAcceptedXViewRoleCoverage
import SmzaRp05CurrentSelectedXViewClaims
import SmzaRp05CurrentAcceptedStageReplay
import SmzaRp05CurrentBranchOracleAgreement
import SmzaRp05PhysicalPcsRecordRetention
import SmzaRp05PhysicalHashFppRecordRetention
import SmzaRp05CurrentNonchallengeRecordView
import SmzaRp05ExecutableMerklePaths
import SmzaRp05CurrentAdviceDependentPhysicalMass
import SmzaRp05CurrentSelectedXViewRoleTransfer
import SmzaRp05CurrentSelectedCurrentAdviceEventMass
import SmzaRp05CurrentGroupedContext
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05Current406ActiveFiberEvent
import SmzaRp05Current406EventSpec
import SmzaRp05CurrentPiopRoleEvents
import SmzaRp05CurrentAcceptedEarlierAdvice
import SmzaRp05CurrentExecutedEarlierAdvice
import SmzaRp05CurrentAcceptedFixedEarlierPiopCells
import SmzaRp05CurrentAcceptedPiopCausalCoverage
import SmzaRp05CurrentAcceptedPiopStageEventCoverage
import SmzaRp05CurrentAcceptedCausalPayloadIdentity
import SmzaRp05CurrentAcceptedCausalPayloads
import SmzaRp05CurrentCausalNonchallengeRetention
import SmzaRp05CurrentFixedEarlierAdvice
import SmzaRp05AdaptiveRetainedAdviceTransport
import SmzaRp05PhysicalProgramBridge
import SmzaRp05ExecutablePcsClosureSampling
import SmzaRp05ExecutablePcsClosureClean
import SmzaRp05CurrentAcceptedPiopFailureEvents
import SmzaRp05CurrentAcceptedPiopRecordedOutputs
import SmzaRp05CurrentAcceptedRoleQueryReadback
import SmzaRp05CurrentAcceptedNonleafRoleReadback
import SmzaRp05CurrentAcceptedFilteredRoleTraces
import SmzaRp05CurrentGroupedVerifierReplay
import SmzaRp05CurrentAcceptedPiopOutputBinding
import SmzaRp05CurrentFullOrRoleExtraction

/-! # Transfer selected X-view role evidence to its mixed completion

The accepted-classifier evidence is evaluated under a claims-completing
database.  This module transports its exact execution and PCS records to the
literal fixed/active completion from the selected mixed support.  Both tables
satisfy the same branch claims, so their program reads and verifier transcript
are stable; equality of the nonchallenge views preserves the filtered source
records used by the current decoder.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopExtractionFailureEvent

open scoped Classical
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.CmsCompressedOracle (Basis)
open SmzaRoleDomainConditioning (ActiveKey)
open SmzaRp05ConditionedExecution
  (ActiveState ActiveMemory FixedTable XKey xView activeXView
    mergeFixedActive)
open SmzaRp05CurrentAdaptiveExecution (Context Work)
open SmzaRp05CurrentSelectedChallengeClaims
  (SelectedWork nonchallengeRawKeySet recognizedActiveChallengeClaims
    branchXRoleSelector)
open SmzaRp05CurrentSelectedXViewClaims (selected_support_supplies_full_branch_claims)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass (selectedRoleState)
open SmzaRp05CurrentAcceptedXViewRoleCoverage
  (currentAcceptedXViewRoleSelector grouped_filtered_records_eq_of_same_xview)
open SmzaRp05CurrentFullOrRoleExtraction (currentAcceptedXViewFailureRoleSelector)
open SmzaRp05CurrentSelectedXViewRoleTransfer (CurrentAcceptedXViewRoleEvidence)
open SmzaRp05CurrentAcceptedStageReplay
  (replay_execution_stages_of_verifier_record_eq
    replay_pcs_stages_of_verifier_record_eq execution_transcript_success)
open SmzaRp05CurrentBranchOracleAgreement
  (record_eq_of_agrees_on_left_reads eval_eq_of_agrees_on_left_reads
    same_branch_claims_agree_on_record_reads)
open SmzaRp05CurrentNonchallengeRecordView
  (grouped_erased_raw_records_eq_of_nonchallenge_key_agreement)
open SmzaRp05PhysicalPcsRecordRetention
  (execution_pcs_records_retained_in_verifier)
open SmzaRp05PhysicalHashFppRecordRetention (pcs_hash_fpp_records_retained)
open SmzaRp05ExecutableMerkleVerifier (Program.bind_log_left Program.bind_log_right)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05PhysicalAcceptedReplayLite (Branches)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05PcsToFinalProgram (sameProofRows)
open SmzaRp05CurrentAcceptedFilteredClassification (CurrentNoWitnessLabelOutcome)
open SmzaRp05CurrentAcceptedQueryExtraction (CurrentDecoderOutcome)
open SmzaRp05CurrentRetainedQuerySupport (measuredDataTable measuredMaskTable)
open SmzaRp05PcsHashFppMiddle (gammaRows)
open SmzaRp05CurrentTwelveCalculated (currentStageTails)
open SmzaRp05CurrentResponseInputDecoder (responseRuleOfRawInputSelection)
open SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients)
open SmzaChallengeStageTargets (Role)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open SmzaRp05CurrentMaxAgreementRecovery (Query Coefficients)
open SmzaRp05TracePrefixes (rootOracle)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
  (V8PublicStatement encodePublicStatement)
open SmzaRp05ExecutableMerkleVerifier (Oracle)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open SmzaRp05GroupedSuffix (GroupCounter groupZero)
open V8Smz9CoherentMerkleInstrument (rawRecords)

open scoped Classical
open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.CanonicalBytes (encodeLE)
open HegemonCrypto.CmsCompressedOracle (Basis)
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.CmsAdaptiveClaimBridge (workspaceEventProjection)
open SmzaRp05ActualEventRecertification (event)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRoleDomainConditioning (ActiveKey)
open SmzaRp05ConditionedExecution
  (ActiveState XKey FixedTable fixedFiberToActive otherRoleTransform mergeFixedActive)
open SmzaRp05CurrentAdaptiveExecution (Context)
open SmzaRp05CurrentAdaptiveExecution (CmsState)
open SmzaRp05CurrentAdaptiveExecution (Work)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05RelationRefinement (relationModel GeneratedCertificates RelationDsl)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05ExecutablePcsClosureStatement (statementBindingWords)
open SmzaRp05PcsToFinalProgram (sameProofRows)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (answer_log_group_keys_represented)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative groupZero)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaRp05CurrentSelectedChallengeClaims
  (recognizedActiveChallengeClaims nonchallengeRawKeySet
    nonchallenge_raw_key_set_unrecognized branchXRoleSelector)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass (selectedRoleState)
open SmzaRp05AdaptiveRetainedAdviceTransport (physical_run_to_mixed_same_fiber)
open SmzaRp05CurrentSelectedXViewRoleTransfer
  (selected_xview_role_replays_on_completion)
open SmzaRp05CurrentAcceptedXViewRoleCoverage (currentAcceptedXViewRoleSelector)
open SmzaRp05CurrentSelectedXViewClaims (selected_support_supplies_full_branch_claims)
open SmzaRp05CurrentAdviceDependentPhysicalMass
  (currentAdviceEventSpec currentAdviceActiveContext currentAdviceContextAtFixed)
open SmzaRp05CurrentFixedEarlierAdvice (currentFixedAdvice)
open SmzaRp05CurrentAcceptedFixedEarlierReadback (currentFixedEarlierAdviceFamily)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05Current406ActiveFiberEvent (current406_base_merged_iff_active)
open SmzaRp05Current406EventSpec
  (current406Base current406EventSpec currentRoleEvent406Explicit)
open SmzaRp05CurrentPiopRoleEvents (PiopRole currentPiopRoleEvent406)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchKeys branchAnswers branchClaims branchResult physicalRun rawLog)
open SmzaRp05ExecutablePcsClosure (ExecutionStages transcriptProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05CurrentGroupedVerifierReplay (accepted_grouped_claims_supply_verifier_replay)
open SmzaRp05TracePrefixes (TypedRoutes Trace Payload)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext)
open SmzaRecordedTracePath (RecordsCollisionFree)
open SmzaChallengeStageTargets (StageQuery)
open SmzaRp05CurrentRoleLabels (targetOfRaw)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes)
open SmzaRp05AcceptedRoleLabels (EarlierReadback CausalPayloads causalTrace)
open SmzaRp05CurrentPiopRoleEvents
  (current_causal_matrix_failure_is_label_bad current_causal_opening_failure_is_label_bad)
open SmzaRp05ExecutablePcsClosureSampling (execution_stages_clean_matrix)
open SmzaRp05CurrentAcceptedPiopFailureEvents
  (current_piop_event_of_readbacks accepted_opening_call_role_readback)
open SmzaRp05CurrentAcceptedPiopRecordedOutputs
  (accepted_matrix_call_and_vector accepted_opening_call_and_vector)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05CurrentAcceptedNonleafRoleReadback (accepted_stages_raw_nonleaf_outer_preambles)
open SmzaRp05CurrentAcceptedFilteredRoleTraces
  (current_stages_supply_filtered_role_traces currentOuterTarget)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix groupKeyOf groupEncode groupAddress group_address_encode)
open SmzaRp05CertifiedReplaySchedule (ordinary_counter_roundtrip)
open SmzaRp05ExecutableChallengeStage (counterInput)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05ChallengeRecordErasure (global_extract_filtered_erase_challenge)
open SmzaRp05CurrentPiopRoleEvents (PiopRole)
open SmzaRp05CurrentFixedEarlierAdvice (currentFixedAdvice)
open SmzaRp05CurrentAcceptedFixedEarlierReadback
  (currentFixedEarlierAdviceFamily_active)
open SmzaRp05CurrentGroupedClaimRetention (actual_program_grouped_claims_replay_and_retain)
open SmzaRp05CurrentCausalNonchallengeRetention (accepted_execution_causal_record_memberships)
open SmzaRp05CurrentAcceptedEarlierAdvice
  (accepted_execution_supplies_earlier_advice_of_nonchallenge_retention)
open SmzaRp05CurrentExecutedEarlierAdvice (currentOracleAllAdvice)
open SmzaRp05CurrentAcceptedFixedEarlierPiopCells (same_stage_fixed_piop_earlier_readback)
open SmzaRp05CurrentAcceptedPiopCausalCoverage (same_stage_piop_failure_has_causal_readback)
open SmzaRp05CurrentAcceptedPiopStageEventCoverage (accepted_execution_piop_failure_yields_role_event)
open SmzaRp05CurrentAcceptedPiopFailureEvents
  (current_piop_event_of_readbacks accepted_opening_call_role_readback)
open SmzaRp05CurrentAcceptedPiopRecordedOutputs
  (accepted_matrix_call_and_vector accepted_opening_call_and_vector)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05CurrentAcceptedPiopOutputBinding (actual_grouped_piop_matrix_route_output)
open SmzaRp05CurrentAcceptedFilteredRoleTraces
  (current_stages_supply_filtered_role_traces currentOuterTarget)
open SmzaRp05CurrentAcceptedNonleafRoleReadback (accepted_stages_raw_nonleaf_outer_preambles)
open SmzaRp05CurrentGroupedVerifierReplay (accepted_grouped_claims_supply_verifier_replay)
open SmzaRp05ExecutablePcsClosureSampling (execution_stages_clean_matrix)
open SmzaRp05ExecutableChallengeStage (counterInput)
open SmzaRp05CertifiedReplaySchedule (ordinary_counter_roundtrip)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix groupKeyOf groupEncode groupAddress group_address_encode)
open SmzaRp05CurrentAcceptedCausalPayloadIdentity (causal_payloads_unique)
open SmzaRp05CurrentAcceptedCausalPayloads (current_causal_payloads_and_targets_of_stages)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords global_extract_filtered_erase_challenge)
open SmzaRp04StatementRecordFilter (oneStatementFilter nonleafFilter)
open SmzaRp05TracePrefixes (TypedRoutes Trace)
open SmzaRp05CurrentRoleLabels (currentOuter targetOfRaw)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes)
open SmzaRp05AcceptedRoleLabels (causalTrace)
open SmzaRp05CurrentGroupedContext (parsed_representative_determines_grouped_counter_calls)
open V8Smz9CoherentMerkleGeometry (extract)
open SmzaRp04StatementRecordFilter (oneStatementFilter)
open SmzaRp05CurrentAcceptedCausalPayloads (Records)
open SmzaRp05PhysicalAcceptedReplayLite (physicalRun)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8SmzaOracleParser (RawDigest RawInput)
open HegemonCrypto.SmallWoodTranscript (piopCoefficientDomain)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification (V8PublicStatement)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 30000
set_option maxHeartbeats 1600000
set_option linter.unusedSectionVars false

local instance : DecidableEq RawInput :=
  SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq

local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

section FailureReplay

attribute [local irreducible]
  HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates.currentDsl
  HegemonCrypto.SmallWood.SmzaRp05RelationRefinement.relationModel
  HegemonCrypto.SmallWood.SmzaRp04ChronologicalAlgebra.piopMatrixBadEvent
  HegemonCrypto.SmallWood.SmzaRp04ChronologicalAlgebra.piopOpeningBadEvent

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

theorem selected_xview_failure_role_replays_on_completion
    (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (fuel : Nat)
    (ctx : Context (Key := Key
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (keyBytesExact : ∀ key, ctx.keyBytes key =
      SmzaRp05GroupedSuffix.groupRepresentative (included
        (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
        key))
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire))
    (fixed : FixedTable ctx blockCap)
    (initial : ActiveState ctx blockCap)
    (basis : Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter) (ActiveMemory ctx))
    (challengeClaims : ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims ctx blockCap
        (encode (producer.bind fun wire =>
          verifierProgram ns currentDsl statement pending nonce wire)) groupedDecode
        (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
        branch) basis.database)
    (selectorSupport : selectedRoleState ctx blockCap
      (encode (producer.bind fun wire =>
        verifierProgram ns currentDsl statement pending nonce wire)) groupedDecode
      (producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire)
      branch fixed initial
      (fun view _work => currentAcceptedXViewFailureRoleSelector producer ns statement pending
        nonce fallback fuel ctx ctx.role branch view) basis ≠ 0) :
    CurrentAcceptedXViewRoleEvidence producer ns statement pending nonce fallback fuel
      ctx.role (mergeFixedActive ctx blockCap fixed basis.database) := by
  classical
  let program := producer.bind fun wire =>
    verifierProgram ns currentDsl statement pending nonce wire
  let select := fun (view : XKey (nonchallengeRawKeySet ctx) →
      Option (VectorOutput GroupCounter)) (_work : Work (Counter := GroupCounter)
      (BaseWork := BaseWork)) =>
    currentAcceptedXViewFailureRoleSelector producer ns statement pending nonce fallback
      fuel ctx ctx.role branch view
  let merged := mergeFixedActive ctx blockCap fixed basis.database
  let keys := nonchallengeRawKeySet ctx
  let unrecognized := SmzaRp05CurrentSelectedChallengeClaims.nonchallenge_raw_key_set_unrecognized ctx
  have selectedJoin := selected_support_supplies_full_branch_claims ctx blockCap
    (encode program) groupedDecode program branch fixed initial select basis
    selectorSupport challengeClaims
  have branchSelector := selectedJoin.1
  have mergedClaims := selectedJoin.2.1
  have mergedView := selectedJoin.2.2
  have selectorOnActive := branchSelector.1
  have selectorAtView : currentAcceptedXViewFailureRoleSelector producer ns statement pending
      nonce fallback fuel ctx ctx.role branch
      (activeXView ctx blockCap keys unrecognized basis.database) := by
    exact selectorOnActive
  dsimp only [currentAcceptedXViewFailureRoleSelector] at selectorAtView
  rcases selectorAtView with ⟨completion, completionView, completionClaims,
    completionEvidence⟩
  let completionViewFn := xView keys completion
  have completionViewEq : completionViewFn =
      activeXView ctx blockCap keys unrecognized basis.database := by
    funext key
    exact completionView key.val key.property
  have completionMergedView : xView keys completion = xView keys merged := by
    calc
      xView keys completion = activeXView ctx blockCap keys unrecognized basis.database :=
        completionViewEq
      _ = xView keys merged := mergedView.symm
  let leftOracle := finiteGroupedDatabaseOracle program completion fallback
  let rightOracle := finiteGroupedDatabaseOracle program merged fallback
  rcases completionEvidence with ⟨completionGood, completionEvidence⟩
  rcases completionEvidence with ⟨completionOracle, oracleEq, wire, transcript,
    producerOk, verifierOk, transcriptOk, execution, pcs, coordinates, query,
    input, ordered, image, indexes, inputMember, hashMember, currentOutcome,
    labelOutcome, roleFailure⟩
  have oracleSame : completionOracle = leftOracle := by exact oracleEq
  subst completionOracle
  have agrees := same_branch_claims_agree_on_record_reads program branch
    completion merged completionClaims mergedClaims fallback fallback
  have producerReadAgree : ∀ raw, (raw, leftOracle raw) ∈
      (producer.record leftOracle).2 → leftOracle raw = rightOracle raw := by
    intro raw member
    have included := Program.bind_log_left leftOracle producer
      (fun output => verifierProgram ns currentDsl statement pending nonce output)
      wire producerOk member
    exact agrees raw included
  have verifierReadAgree : ∀ raw, (raw, leftOracle raw) ∈
      ((verifierProgram ns currentDsl statement pending nonce wire).record leftOracle).2 →
        leftOracle raw = rightOracle raw := by
    intro raw member
    have included := Program.bind_log_right leftOracle producer
      (fun output => verifierProgram ns currentDsl statement pending nonce output)
      wire producerOk member
    exact agrees raw included
  have producerEvalEq := eval_eq_of_agrees_on_left_reads producer leftOracle rightOracle
    producerReadAgree
  have producerRight : producer.eval rightOracle = some wire :=
    producerEvalEq.symm.trans producerOk
  have verifierRecordEq := record_eq_of_agrees_on_left_reads
    (verifierProgram ns currentDsl statement pending nonce wire) leftOracle rightOracle
    (by
      intro raw member
      have included := Program.bind_log_right leftOracle producer
        (fun output => verifierProgram ns currentDsl statement pending nonce output)
        wire producerOk member
      exact agrees raw included)
  have verifierEvalEq := eval_eq_of_agrees_on_left_reads
    (verifierProgram ns currentDsl statement pending nonce wire) leftOracle rightOracle
    (by
      intro raw member
      have included := Program.bind_log_right leftOracle producer
        (fun output => verifierProgram ns currentDsl statement pending nonce output)
        wire producerOk member
      exact agrees raw included)
  have verifierRight : (verifierProgram ns currentDsl statement pending nonce wire).eval
      rightOracle = some () := verifierEvalEq.symm.trans verifierOk

  let executionRight := replay_execution_stages_of_verifier_record_eq ns currentDsl
    statement pending nonce wire leftOracle rightOracle transcript execution verifierRecordEq
  let pcsRight := replay_pcs_stages_of_verifier_record_eq ns currentDsl statement
    pending nonce wire leftOracle rightOracle transcript execution pcs verifierRecordEq
  have transcriptRight := execution_transcript_success ns currentDsl statement pending
    nonce wire rightOracle transcript executionRight
  let erasedRight := SmzaRp05ChallengeRecordErasure.eraseChallengeRecords
    (rawRecords
      (fun key => SmzaRp05GroupedSuffix.groupRepresentative (included program key))
      (vectorOutputBytes groupZero) merged)
  let filteredRight := SmzaRp04StatementRecordFilter.oneStatementFilter
    (SmzaRp05FilteredReadback.globalLeafStatement ns) statement.toBytes erasedRight
  have filteredEq := grouped_filtered_records_eq_of_same_xview producer ns statement
    pending nonce ctx keyBytesExact completion merged completionMergedView
  have erasedEq : SmzaRp05ChallengeRecordErasure.eraseChallengeRecords
      (rawRecords (fun key => SmzaRp05GroupedSuffix.groupRepresentative
        (included program key)) (vectorOutputBytes groupZero) completion) = erasedRight := by
    exact grouped_erased_raw_records_eq_of_nonchallenge_key_agreement program
      completion merged (by
        intro key nonchallenge
        have ctxNonchallenge : SmzaChallengeStageTargets.parseStageQuery
            (ctx.keyBytes key) = none := by
          rw [keyBytesExact]
          exact nonchallenge
        have member : key ∈ keys :=
          Finset.mem_filter.mpr ⟨Finset.mem_univ _, ctxNonchallenge⟩
        have sameCell := congrFun completionMergedView ⟨key, member⟩
        simpa [xView] using sameCell)
  have postRootEq : pcsRight.post.root = pcs.post.root := rfl
  have gammaRowsEq : gammaRows pcsRight.post = gammaRows pcs.post := rfl
  have headsEq : pcsRight.heads = pcs.heads := rfl
  have tailsEq : currentStageTails
      (sameProofRows executionRight.middle.pcs executionRight.piop) =
      currentStageTails (sameProofRows execution.middle.pcs execution.piop) := rfl
  have pointsEq : (fun opening : Fin 6 => (List.ofFn fun j : Fin 6 =>
      V8Smz9PiopReconstruction.points executionRight.opening j).getD opening.val 0) =
      (fun opening : Fin 6 => (List.ofFn fun j : Fin 6 =>
      V8Smz9PiopReconstruction.points execution.opening j).getD opening.val 0) := rfl
  have openingInputEq : pcsRight.openingInput = pcs.openingInput := rfl
  have matrixEq : executionRight.matrix = execution.matrix := rfl
  have openingEq : executionRight.opening = execution.opening := rfl
  have currentOutcomeRight : CurrentDecoderOutcome
      (measuredDataTable ns filteredRight fuel pcsRight.post.root)
      (measuredMaskTable ns filteredRight fuel pcsRight.post.root)
      (responseRuleOfRawInputSelection (fun _ : Coefficients => input))
      (sampledCoefficients (gammaRows pcsRight.post)) pcsRight.heads
      (currentStageTails (sameProofRows executionRight.middle.pcs executionRight.piop))
      (fun opening => (List.ofFn fun j : Fin 6 =>
        V8Smz9PiopReconstruction.points executionRight.opening j).getD opening.val 0)
      query := by
    unfold filteredRight erasedRight program
    rw [← filteredEq, postRootEq, gammaRowsEq, headsEq, tailsEq, pointsEq]
    exact currentOutcome
  have labelOutcomeRight : CurrentNoWitnessLabelOutcome ns statement pending nonce wire
      rightOracle transcript executionRight pcsRight erasedRight fuel input query := by
    change CurrentNoWitnessLabelOutcome ns statement pending nonce wire
      leftOracle transcript execution pcs erasedRight fuel input query
    exact (congrArg (fun records => CurrentNoWitnessLabelOutcome ns statement pending
      nonce wire leftOracle transcript execution pcs records fuel input query)
      erasedEq).mp labelOutcome
  have roleFailureRight :
      SmzaRp05CurrentAcceptedXViewRoleCoverage.noWitnessRoleFailure ctx.role ns
        statement pending nonce wire rightOracle transcript executionRight pcsRight
        erasedRight fuel input query := by
    change SmzaRp05CurrentAcceptedXViewRoleCoverage.noWitnessRoleFailure ctx.role ns
      statement pending nonce wire leftOracle transcript execution pcs
      erasedRight fuel input query
    exact (congrArg (fun records =>
      SmzaRp05CurrentAcceptedXViewRoleCoverage.noWitnessRoleFailure ctx.role ns
        statement pending nonce wire leftOracle transcript execution pcs
        records fuel input query) erasedEq).mp roleFailure
  have filteredGoodRight : SmzaRecordedTracePath.RecordsCollisionFree filteredRight := by
    exact (congrArg SmzaRecordedTracePath.RecordsCollisionFree filteredEq).mp completionGood
  have inputMemberRight : (input, execution.hashFpp) ∈ filteredRight := by
    exact (congrArg (fun records => (input, execution.hashFpp) ∈ records) filteredEq).mp
      inputMember
  have hashRecordEq :
      (pcs.hashProgram.record leftOracle).2 =
        (pcs.hashProgram.record rightOracle).2 := by
    apply congrArg Prod.snd
    apply record_eq_of_agrees_on_left_reads pcs.hashProgram leftOracle rightOracle
    intro raw member
    have intoPcs := pcs_hash_fpp_records_retained ns execution.openingPending
      wire.hPiop (sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement) wire.tapes
      wire.paths leftOracle execution.hashFpp execution.pcsPending pcs
      execution.pcsExecuted raw (leftOracle raw) member
    have transcriptSuccess := execution_transcript_success ns currentDsl statement
      pending nonce wire leftOracle transcript execution
    have intoVerifier := execution_pcs_records_retained_in_verifier ns currentDsl
      statement pending nonce wire leftOracle transcript execution transcriptSuccess
    exact agrees raw (Program.bind_log_right leftOracle producer
      (fun output => verifierProgram ns currentDsl statement pending nonce output)
      wire producerOk (intoVerifier (raw, leftOracle raw) intoPcs))
  have hashProgramRight : pcsRight.hashProgram = pcs.hashProgram := rfl
  have hashFppRight : executionRight.hashFpp = execution.hashFpp := rfl
  have hashMemberRight : (input, executionRight.hashFpp) ∈
      (pcsRight.hashProgram.record rightOracle).2 := by
    rw [hashProgramRight, hashFppRight, ← hashRecordEq]
    exact hashMember
  dsimp only [CurrentAcceptedXViewRoleEvidence]
  exact ⟨filteredGoodRight, ⟨wire, transcript, producerRight, verifierRight, transcriptRight,
    executionRight, pcsRight, coordinates, query, input, ordered, image, indexes,
    inputMemberRight, hashMemberRight, currentOutcomeRight, labelOutcomeRight,
    roleFailureRight⟩⟩

end FailureReplay

private def acceptedFilteredRecords
    {Result : Type} (program : Program Result)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (ns : SmzaRp05LeafNamespace.Namespace) (statement : SmzaRp05StatementNamespace.Statement) :=
  oneStatementFilter (SmzaRp05FilteredReadback.globalLeafStatement ns) statement.toBytes
    (eraseChallengeRecords
      (rawRecords (fun key => groupRepresentative (included program key))
        (vectorOutputBytes groupZero) database))

private theorem accepted_execution_selected_piop_failure_yields_role_event
    (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool) (nonce : Fin (2 ^ 32))
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
    (accepted : branchResult groupedDecode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
      branch = some ())
    (database : Database
      (Key (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (branchClaims
        (branchKeys (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) branch)
        (branchAnswers (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) branch))
      database)
    (fallback : RawDigest) [Fintype RawDigest]
    (certificates : GeneratedCertificates dsl)
    (bounded : ModelWithinProtocol (relationModel dsl certificates))
    (outerFuel : Nat) (outerEnough : 28 ≤ outerFuel)
    (authorized : Finset (List Byte)) (fresh : statement.toBytes ∉ authorized)
    (wire : ExistingProofFieldView)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback) transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement) wire.tapes wire.paths
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback) execution.hashFpp execution.pcsPending)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback) = some wire)
    (verifierAccepted : (verifierProgram ns dsl statement pending nonce wire).eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback) = some ())
    (transcriptSuccess : (transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire).eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback) = some transcript)
    (collisionFree : RecordsCollisionFree
      (acceptedFilteredRecords
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database ns statement))
    (advice : (role : SmzaChallengeStageTargets.Role) →
      SmzaRp05TracePrefixes.AllEarlierTables (relationModel dsl certificates) role)
    (messages : CausalPayloads ns
      (extract (globalOnlineNext ns)
        (acceptedFilteredRecords
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          database ns statement)
        28 .decs pcs.openingDigest))
    (earlier : EarlierReadback (relationModel dsl certificates) statement
      (fun role => advice role statement) messages
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) execution.matrix execution.opening)
    (source : V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140)
    (recovered : SmzaRp05CurrentTracePrefixes406.currentSourceDecoder406
      (SmzaRp05AcceptedRoleLabels.causalOracle ns
        (extract (globalOnlineNext ns)
          (acceptedFilteredRecords
            (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
            database ns statement) 28 .decs pcs.openingDigest)) messages.fpp
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) = some source)
    (which : PiopRole)
    (failure : match which with
      | .matrix =>
          (¬ HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
              ((relationModel dsl certificates).recoveredCandidate statement source.data).system ∧
            execution.matrix ∈ SmzaRp04ChronologicalAlgebra.piopMatrixBadEvent
              ((relationModel dsl certificates).recoveredCandidate statement source.data))
      | .opening =>
          execution.opening ∈ SmzaRp04ChronologicalAlgebra.piopOpeningBadEvent
            ((relationModel dsl certificates).recoveredCandidate statement source.data) execution.matrix
            (SmzaRp05TracePrefixes.piopResponse messages.piop)) :
    currentPiopRoleEvent406 (relationModel dsl certificates) ns
      (fun key => groupRepresentative
        (included (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) key))
      groupZero (currentGroupedRoutes (relationModel dsl certificates) bounded) which
      (advice which.toRole)
      outerFuel 28 authorized database := by
  classical
  let program := producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire
  let oracle := finiteGroupedDatabaseOracle program database fallback
  let fullRecords := rawRecords (fun key => groupRepresentative (included program key))
    (vectorOutputBytes groupZero) database
  let filteredRecords := acceptedFilteredRecords program database ns statement
  obtain ⟨replayWire, producerSuccess₂, _verifierAccepted₂, retained'⟩ :=
    accepted_grouped_claims_supply_verifier_replay producer ns dsl statement
      pending nonce branch accepted database claims fallback
  have sameWire : wire = replayWire := Option.some.inj
    (producerSuccess.symm.trans producerSuccess₂)
  subst replayWire
  have retainedOuter := accepted_stages_raw_nonleaf_outer_preambles
    producer ns dsl statement pending nonce database fallback wire transcript execution pcs
    verifierAccepted transcriptSuccess outerFuel outerEnough collisionFree retained'
  have filteredTraces := current_stages_supply_filtered_role_traces
    producer ns dsl statement pending nonce database fallback wire transcript execution pcs
    verifierAccepted transcriptSuccess 28 (by decide) collisionFree retained'
  let model := relationModel dsl certificates
  let actualTrace : Trace := extract (globalOnlineNext ns) filteredRecords 28 .decs pcs.openingDigest
  have rawMatrixTraceEq := global_extract_filtered_erase_challenge ns fullRecords
    (fun input => globalLeafStatement ns input = none ∨
      globalLeafStatement ns input = some statement.toBytes)
    28 .fpp execution.hashFpp
  have rawOpeningTraceEq := global_extract_filtered_erase_challenge ns fullRecords
    (fun input => globalLeafStatement ns input = none ∨
      globalLeafStatement ns input = some statement.toBytes)
    28 .piop wire.hPiop
  let keyBytes := fun key : Key program => groupRepresentative (included program key)
  have stageClean : transcript.pendingXofFailure = false := by
    obtain ⟨cleanTranscript, cleanSuccess, clean, _, _⟩ :=
      SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl
        statement pending statement.toBytes (statementBindingWords statement) nonce wire oracle
        verifierAccepted
    have transcriptEq : cleanTranscript = transcript :=
      Option.some.inj (cleanSuccess.symm.trans transcriptSuccess)
    simpa [transcriptEq] using clean
  -- The caller's readback is explicitly indexed by the actual filtered trace;
  -- the following role traces and calls are reconstructed from this run.
  have matrixOutputs := accepted_matrix_call_and_vector producer ns dsl statement pending nonce
    branch database claims fallback wire producerSuccess transcript transcriptSuccess
    execution pcs stageClean certificates bounded
  cases which with
  | matrix =>
      let matrixFailure := failure
      obtain ⟨vector, recorded, sampled⟩ := matrixOutputs
      let callInput := counterInput piopCoefficientDomain execution.hashFpp 0
      let query : StageQuery := ⟨.piopMatrix, execution.hashFpp, 0, 0⟩
      let zeroCounter : Fin (2 ^ 64) := ⟨0, by norm_num⟩
      let leading : RawInput :=
        encodeLE 8 V8SmzaOracleParser.profileDomain.length ++
          V8SmzaOracleParser.profileDomain ++ encodeLE 8 piopCoefficientDomain.length ++
          piopCoefficientDomain ++ encodeLE 8 8 ++ List.ofFn execution.hashFpp
      have parsedZero : parseStageQuery (leading ++ encodeLE 8 0) = some query := by
        change parseStageQuery (counterInput piopCoefficientDomain execution.hashFpp 0) = _
        simpa only [SmzaChallengeStageTargets.roleDomain,
          SmzaRp05ExecutableChallengeStage.counterInput, zeroCounter, Fin.val_mk, query] using
          ordinary_counter_roundtrip .piopMatrix (by decide) execution.hashFpp zeroCounter
      let rolePrefix : CanonicalRolePrefix :=
        ⟨.piopMatrix, leading, ⟨query, parsedZero, rfl⟩⟩
      have encoded : groupEncode (rolePrefix, groupZero) = callInput := by
        change leading ++ encodeLE 8 0 = _
        rfl
      have represented := answer_log_group_keys_represented groupedDecode program branch
        (callInput, vector) recorded
      have keyIdentity : included program (encode program callInput) = Sum.inl rolePrefix := by
        calc
          included program (encode program callInput) = groupKeyOf callInput := represented
          _ = Sum.inl rolePrefix := by
            change (groupAddress callInput).1 = _
            rw [← encoded]
            exact congrArg Prod.fst (group_address_encode rolePrefix groupZero)
      have representativeParsed : parseStageQuery (groupRepresentative
          (included program (encode program callInput))) = some query := by
        have representativeParsed' :
            parseStageQuery (groupRepresentative (Sum.inl rolePrefix)) = some query := by
          simpa only [groupRepresentative, groupEncode, rolePrefix, groupZero,
            V8Smz9CoherentVectorMerkle.canonicalRepresentative,
            V8Smz9RawCounterCompiler.boundedCounterInput,
            V8Smz9RawCounterCompiler.counterInput, Fin.val_mk] using parsedZero
        rw [keyIdentity]
        exact representativeParsed'
      obtain ⟨_, _, _, _, targetRead, stored, _, _⟩ :=
        current_actual_grouped_role_call_readback program branch (callInput, vector) recorded
          database claims fallback .piopMatrix query representativeParsed rfl rfl
      have outerReadback : currentOuter ns keyBytes .piopMatrix outerFuel
          (nonleafFilter (globalLeafStatement ns) fullRecords) (encode program callInput) =
            some statement.toBytes := by
        unfold currentOuter
        change SmzaRp05CurrentRoleLabels.preambleFromTrace ns .piopMatrix
          (extract (globalOnlineNext ns) (nonleafFilter (globalLeafStatement ns) fullRecords)
            outerFuel (targetOfRaw .piopMatrix (keyBytes (encode program callInput))).1
              (targetOfRaw .piopMatrix (keyBytes (encode program callInput))).2) = _
        rw [targetRead]
        change SmzaRp05CurrentRoleLabels.preambleFromTrace ns .piopMatrix
          (extract (globalOnlineNext ns) (nonleafFilter (globalLeafStatement ns) fullRecords)
            outerFuel .fpp execution.hashFpp) = _
        exact retainedOuter .piopMatrix
      have innerReadback : extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes fullRecords)
          28 (targetOfRaw .piopMatrix (keyBytes (encode program callInput))).1
            (targetOfRaw .piopMatrix (keyBytes (encode program callInput))).2 =
          causalTrace actualTrace .piopMatrix := by
        rw [targetRead]
        exact rawMatrixTraceEq.symm.trans (filteredTraces.2 .piopMatrix)
      have labelBad := current_causal_matrix_failure_is_label_bad model ns statement
        actualTrace messages (fun role => advice role statement)
        (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
          (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) execution.matrix execution.opening
        earlier source recovered (currentGroupedRoutes model bounded statement) vector sampled
        matrixFailure.1 matrixFailure.2
      exact (current_piop_event_of_readbacks model ns keyBytes groupZero
        (currentGroupedRoutes model bounded) .matrix
        (advice .piopMatrix) outerFuel 28 authorized statement fresh
        (encode program callInput) vector database query representativeParsed rfl stored
        outerReadback actualTrace innerReadback labelBad)
  | opening =>
      let openingFailure := failure
      obtain ⟨counter, vector, counterBound, recorded, sampled⟩ :=
        accepted_opening_call_and_vector producer ns dsl statement pending nonce branch database
          claims fallback wire producerSuccess transcript transcriptSuccess execution pcs
          stageClean certificates bounded
      let callInput := SmzaRp05CurrentOpeningProgram.openingCounterInput
        wire.hPiop nonce.val counter
      obtain ⟨_rolePrefix, _keyIdentity, representativeParsed, stored⟩ :=
        accepted_opening_call_role_readback program branch database claims fallback
          wire.hPiop nonce.val (by omega) ⟨counter, by
            rw [SmzaRp05GroupedSuffix.group_block_cap_eq]
            omega⟩ vector recorded
      have targetRead := current_actual_grouped_role_call_readback program branch
        (callInput, vector) recorded database claims fallback .piopOpening
        ⟨.piopOpening, wire.hPiop, nonce.val, 0⟩ representativeParsed rfl rfl
      obtain ⟨_, _, _, _, targetRead, _, _, _⟩ := targetRead
      have outerReadback : currentOuter ns keyBytes .piopOpening outerFuel
          (nonleafFilter (globalLeafStatement ns) fullRecords) (encode program callInput) =
            some statement.toBytes := by
        unfold currentOuter
        change SmzaRp05CurrentRoleLabels.preambleFromTrace ns .piopOpening
          (extract (globalOnlineNext ns) (nonleafFilter (globalLeafStatement ns) fullRecords)
            outerFuel (targetOfRaw .piopOpening (keyBytes (encode program callInput))).1
              (targetOfRaw .piopOpening (keyBytes (encode program callInput))).2) = _
        rw [targetRead]
        change SmzaRp05CurrentRoleLabels.preambleFromTrace ns .piopOpening
          (extract (globalOnlineNext ns) (nonleafFilter (globalLeafStatement ns) fullRecords)
            outerFuel .piop wire.hPiop) = _
        exact retainedOuter .piopOpening
      have innerReadback : extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes fullRecords)
          28 (targetOfRaw .piopOpening (keyBytes (encode program callInput))).1
            (targetOfRaw .piopOpening (keyBytes (encode program callInput))).2 =
          causalTrace actualTrace .piopOpening := by
        rw [targetRead]
        exact rawOpeningTraceEq.symm.trans (filteredTraces.2 .piopOpening)
      have labelBad := current_causal_opening_failure_is_label_bad model ns statement
        actualTrace messages (fun role => advice role statement)
        (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
          (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) execution.matrix execution.opening
        earlier source recovered (currentGroupedRoutes model bounded statement) vector sampled openingFailure
      exact (current_piop_event_of_readbacks model ns keyBytes groupZero
        (currentGroupedRoutes model bounded) .opening
        (advice .piopOpening) outerFuel 28 authorized statement fresh
        (encode program callInput) vector database ⟨.piopOpening, wire.hPiop, nonce.val, 0⟩
        representativeParsed rfl stored outerReadback actualTrace innerReadback labelBad)

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
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (role : Role)
    (branch : Branches groupedDecode
      (actualVerifierProgram producer ns statement pending nonce)) :
    (view : XKey (nonchallengeRawKeySet
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce model bounded role)) →
        Option (VectorOutput GroupCounter)) →
      SmzaRp05CurrentAdaptiveExecution.Work (Counter := GroupCounter)
        (BaseWork := BaseWork) → Prop :=
  let ctx := groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce model bounded role
  fun view _work => currentAcceptedXViewFailureRoleSelector
    producer ns statement pending nonce fallback 28 ctx role branch view

attribute [local irreducible]
  HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates.currentDsl
  HegemonCrypto.SmallWood.SmzaRp05RelationRefinement.candidate
  HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
  HegemonCrypto.SmallWood.SmzaRp04ChronologicalAlgebra.piopMatrixBadEvent
  HegemonCrypto.SmallWood.SmzaRp04ChronologicalAlgebra.piopOpeningBadEvent

theorem grouped_piop_failure_support_implies_current_advice_event_or_missing_claims
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
    (certificates : GeneratedCertificates currentDsl)
    (bounded : ModelWithinProtocol (relationModel currentDsl certificates))
    (blockCap : Role → Nat) (role : PiopRole)
    (positiveDecsMatrixCap : 0 < blockCap .decsMatrix)
    (positivePiopMatrixCap : 0 < blockCap .piopMatrix)
    (branch : Branches groupedDecode
      (actualVerifierProgram producer ns statement pending nonce))
    (fixed : FixedTable
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded role.toRole) blockCap)
    (dummy : ActiveKey role.toRole blockCap
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded role.toRole).keyBytes)
    (state : CmsState
      (Key := Key (actualVerifierProgram producer ns statement pending nonce))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (basis : Basis (ActiveKey role.toRole blockCap
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded role.toRole).keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (SmzaRp05ConditionedExecution.ActiveMemory
        (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
          (relationModel currentDsl certificates) bounded role.toRole)))
    (cap : Nat)
    (support : selectedRoleState
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded role.toRole)
      blockCap (encode (actualVerifierProgram producer ns statement pending nonce))
      groupedDecode (actualVerifierProgram producer ns statement pending nonce)
      branch fixed
      (fixedFiberToActive
        (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
          (relationModel currentDsl certificates) bounded role.toRole)
        blockCap dummy fixed (otherRoleTransform
          (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
            (relationModel currentDsl certificates) bounded role.toRole)
          blockCap state))
      (groupedFailureSelector (BaseWork := BaseWork) producer ns statement pending nonce fallback
        (relationModel currentDsl certificates) bounded role.toRole branch) basis ≠ 0) :
    event (currentAdviceEventSpec
      (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
        (relationModel currentDsl certificates) bounded role.toRole)
      blockCap fixed cap)
      (SmzaRp05ConditionedExecution.activeMemoryEquiv
        (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
          (relationModel currentDsl certificates) bounded role.toRole) basis.workspace)
      basis.database ∨
    ¬ ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims
        (groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce
          (relationModel currentDsl certificates) bounded role.toRole)
        blockCap (encode (actualVerifierProgram producer ns statement pending nonce))
        groupedDecode (actualVerifierProgram producer ns statement pending nonce) branch)
      basis.database := by
  classical
  let model := relationModel currentDsl certificates
  let program := actualVerifierProgram producer ns statement pending nonce
  let ctx := groupedRoleContext (BaseWork := BaseWork) producer ns statement pending nonce model bounded role.toRole
  let select := groupedFailureSelector (BaseWork := BaseWork) producer ns statement pending nonce fallback
    model bounded role.toRole branch
  let fiberInitial := fixedFiberToActive ctx blockCap dummy fixed
    (otherRoleTransform ctx blockCap state)
  by_cases challengeClaims : ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims ctx blockCap (encode program) groupedDecode program branch)
      basis.database
  · have evidence := selected_xview_failure_role_replays_on_completion
      producer ns statement pending nonce fallback 28
      ctx blockCap (by intro key; rfl) branch fixed
      fiberInitial basis challengeClaims support
    rcases evidence with ⟨recordsCollisionFree, wire, transcript, producerSuccess,
      verifierAccepted, transcriptSuccess, execution, pcs, coordinates, query, input,
      ordered, image, indexes, inputMember, hashMember, currentOutcome, labelOutcome,
      roleFailure⟩
    have selectedJoin := selected_support_supplies_full_branch_claims ctx blockCap
      (encode program) groupedDecode program branch fixed
      fiberInitial select basis support challengeClaims
    have mergedClaims := selectedJoin.2.1
    let completed := mergeFixedActive ctx blockCap fixed basis.database
    have claims : ClaimsDatabaseEvent
        (branchClaims (branchKeys (encode program) groupedDecode program branch)
          (branchAnswers (encode program) groupedDecode program branch)) completed := by
      simpa only [completed] using mergedClaims
    let oracle := finiteGroupedDatabaseOracle program completed fallback
    have actualRecord := actual_program_grouped_claims_replay_and_retain
      program branch completed claims fallback
    have actualSuccess : program.eval oracle = some () := by
      change producer.eval oracle = some wire at producerSuccess
      change (verifierProgram ns currentDsl statement pending nonce wire).eval oracle = some ()
        at verifierAccepted
      change (producer.bind fun wire =>
        verifierProgram ns currentDsl statement pending nonce wire).eval oracle = some ()
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
      have inRawLog : call ∈ SmzaRp05PhysicalAcceptedReplayLite.rawLog
          groupedDecode program branch := by
        rw [recordLog] at inProgramRecord
        exact inProgramRecord
      exact actualRecord.2 call inRawLog queryNone
    have causal := same_stage_piop_failure_has_causal_readback role ns statement pending nonce
      wire oracle transcript execution pcs
      (rawRecords (fun key => groupRepresentative (included program key))
        (vectorOutputBytes groupZero) completed)
      verifierAccepted transcriptSuccess nonchallengeRetained recordsCollisionFree
      input query hashMember roleFailure
    rcases causal with ⟨messages, openingRecorded, finalRecorded, hashRetained,
      _rootTraceEq, _piopTraceEq, roleFailureOnTrace⟩
    let causalTrace := V8Smz9CoherentMerkleGeometry.extract
      (SmzaRp05FilteredDecoderInstability.globalOnlineNext ns)
      (SmzaRp04StatementRecordFilter.oneStatementFilter
        (SmzaRp05FilteredReadback.globalLeafStatement ns) statement.toBytes
        (eraseChallengeRecords
          (rawRecords (fun key => groupRepresentative (included program key))
            (vectorOutputBytes groupZero) completed))) 28 .decs pcs.openingDigest
    obtain ⟨payloadTrace, payloadTraceEq, payloadMessages, fppDigest,
      piopDigest, decsDigest⟩ := current_causal_payloads_and_targets_of_stages
      ns currentDsl statement pending nonce wire oracle transcript execution pcs
      (oneStatementFilter
        (SmzaRp05FilteredReadback.globalLeafStatement ns) statement.toBytes
        (eraseChallengeRecords
          (rawRecords (fun key => groupRepresentative (included program key))
            (vectorOutputBytes groupZero) completed))) recordsCollisionFree
      openingRecorded finalRecorded hashRetained
    cases payloadTraceEq
    obtain ⟨cleanTranscript, cleanTranscriptSuccess, transcriptClean, _, _⟩ :=
      SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns currentDsl
        statement pending statement.toBytes (statementBindingWords statement) nonce wire oracle
        verifierAccepted
    have sameTranscript : cleanTranscript = transcript :=
      Option.some.inj (cleanTranscriptSuccess.symm.trans transcriptSuccess)
    have suppliedTranscriptClean : transcript.pendingXofFailure = false := by
      rw [← sameTranscript]
      exact transcriptClean
    have stagesClean :=
      SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix ns currentDsl statement
        pending statement.toBytes (statementBindingWords statement) nonce wire oracle transcript
        execution suppliedTranscriptClean
    have coefficientsClean : pcs.post.pending = false := pcs.pendingReturned.symm.trans stagesClean.1
    have openingCleanData := SmzaRp05ExecutablePcsClosureClean.pcs_stages_clean ns
      execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement) wire.tapes wire.paths
      oracle execution.hashFpp execution.pcsPending pcs stagesClean.1
    have openingClean : execution.openingPending = false := openingCleanData.1
    have actualEarlier := SmzaRp05CurrentExecutedEarlierAdvice.actual_execution_supplies_earlier_readback
      currentDsl certificates statement ns pending nonce wire oracle transcript execution pcs
      (oneStatementFilter (SmzaRp05FilteredReadback.globalLeafStatement ns) statement.toBytes
        (eraseChallengeRecords
          (rawRecords (fun key => groupRepresentative (included program key))
            (vectorOutputBytes groupZero) completed)))
      recordsCollisionFree openingRecorded finalRecorded hashRetained coefficientsClean
      suppliedTranscriptClean openingClean
    obtain ⟨sourceTrace, sourceTraceEq, sourceMessages, oracleEarlier⟩ := actualEarlier
    cases sourceTraceEq
    change SmzaRp05AcceptedRoleLabels.CausalPayloads ns causalTrace at sourceMessages
    have sameMessages : sourceMessages = messages :=
      causal_payloads_unique sourceMessages messages
    have payloadSameMessages : payloadMessages = messages :=
      causal_payloads_unique payloadMessages messages
    have oracleEarlierAtCausalMessages :
        SmzaRp05AcceptedRoleLabels.EarlierReadback model statement
          (fun selected => SmzaRp05CurrentExecutedEarlierAdvice.currentOracleAllAdvice
            model oracle selected statement)
          messages
          (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
            (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) execution.matrix execution.opening := by
      change SmzaRp05AcceptedRoleLabels.EarlierReadback (relationModel currentDsl certificates)
        statement (fun selected => currentOracleAllAdvice
          (relationModel currentDsl certificates) oracle selected statement)
        sourceMessages
        (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
          (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) execution.matrix execution.opening
        at oracleEarlier
      change SmzaRp05AcceptedRoleLabels.EarlierReadback (relationModel currentDsl certificates)
        statement (fun selected => currentOracleAllAdvice
          (relationModel currentDsl certificates) oracle selected statement)
        sourceMessages
        (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
          (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) execution.matrix execution.opening
        at oracleEarlier
      rw [← sameMessages]
      exact oracleEarlier
    let selector : SmzaRp05ConditionedExecution.ActiveMemory ctx →
        Database (ActiveKey ctx.role blockCap ctx.keyBytes)
          (VectorOutput GroupCounter) → Prop := fun
            (work : SmzaRp05ConditionedExecution.ActiveMemory ctx)
            (database : Database (ActiveKey ctx.role blockCap ctx.keyBytes)
              (VectorOutput GroupCounter)) =>
      branchXRoleSelector ctx blockCap (encode program) groupedDecode program branch
        (nonchallengeRawKeySet ctx)
        (by
          intro claim member
          exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
            of_decide_eq_true (List.mem_filter.mp member).2⟩)
        select
        (SmzaRp05ConditionedExecution.activeXView ctx blockCap (nonchallengeRawKeySet ctx)
          (nonchallenge_raw_key_set_unrecognized ctx) database)
        work.original.2.2
    have physicalNonzero : fixedFiberToActive ctx blockCap dummy fixed
        (otherRoleTransform ctx blockCap (physicalRun
          (encode program) groupedDecode program branch state)) basis ≠ 0 := by
      have supportPhysical := support
      unfold selectedRoleState at supportPhysical
      rw [← physical_run_to_mixed_same_fiber ctx blockCap dummy fixed
        (encode program) groupedDecode program branch state] at supportPhysical
      change workspaceEventProjection selector
        (fixedFiberToActive ctx blockCap dummy fixed
          (otherRoleTransform ctx blockCap
            (physicalRun (encode program) groupedDecode program branch state))) basis ≠ 0
        at supportPhysical
      unfold workspaceEventProjection at supportPhysical
      by_cases selectorHit : selector basis.workspace basis.database
      · simpa [selectorHit] using supportPhysical
      · simp [selectorHit] at supportPhysical
    have earlierFixed := same_stage_fixed_piop_earlier_readback
      producer ns currentDsl statement pending nonce branch accepted completed claims
      fallback certificates bounded role.toRole (by cases role <;> simp [PiopRole.toRole])
      (currentFixedAdvice ctx blockCap fixed) 28 28 (fun _ => ∅) blockCap dummy fixed
      state basis physicalNonzero positiveDecsMatrixCap positivePiopMatrixCap wire
      producerSuccess verifierAccepted transcript transcriptSuccess execution pcs messages
      (by rw [← payloadSameMessages]; exact decsDigest)
      (by rw [← payloadSameMessages]; exact fppDigest)
      (by rw [← payloadSameMessages]; exact piopDigest) oracleEarlierAtCausalMessages
    let adviceFamily : (selected : Role) → AllEarlierTables model selected :=
      fun selected => currentFixedEarlierAdviceFamily ctx blockCap fixed oracle selected
    cases role with
    | matrix =>
        rcases roleFailureOnTrace with ⟨source, recovered, notFull, matrixBad⟩
        have matrixFailure :
            (¬ HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
                ((relationModel currentDsl certificates).recoveredCandidate statement source.data).system ∧
              execution.matrix ∈ SmzaRp04ChronologicalAlgebra.piopMatrixBadEvent
                ((relationModel currentDsl certificates).recoveredCandidate statement source.data)) :=
          ⟨notFull, matrixBad⟩
        have selectedStageRoleEvent := accepted_execution_selected_piop_failure_yields_role_event
          producer ns currentDsl statement pending nonce branch accepted completed claims fallback
          certificates bounded 28 (by decide) ∅ (by simp) wire transcript execution pcs
          producerSuccess verifierAccepted transcriptSuccess recordsCollisionFree
          adviceFamily messages earlierFixed source recovered .matrix matrixFailure
        let adjusted := { ctx with advice := currentFixedAdvice ctx blockCap fixed }
        have ctxRole : ctx.role = .piopMatrix := rfl
        have adviceEq : adviceFamily .piopMatrix = currentFixedAdvice ctx blockCap fixed := by
          change currentFixedEarlierAdviceFamily ctx blockCap fixed oracle ctx.role = _
          exact currentFixedEarlierAdviceFamily_active ctx blockCap fixed oracle
        have baseEvent : current406Base adjusted ∅ completed := by
          change currentRoleEvent406Explicit model ns ctx.keyBytes ctx.counter ctx.routes
            .piopMatrix (currentFixedAdvice ctx blockCap fixed) 28 28 ∅ completed
          change currentPiopRoleEvent406 model ns ctx.keyBytes ctx.counter ctx.routes .matrix
            (currentFixedAdvice ctx blockCap fixed) 28 28 ∅ completed
          rw [← adviceEq]
          exact selectedStageRoleEvent
        have activeEvent := (current406_base_merged_iff_active adjusted blockCap fixed
          basis.database ∅).mp baseEvent
        have specEventEq : event (currentAdviceEventSpec ctx blockCap fixed cap)
            (SmzaRp05ConditionedExecution.activeMemoryEquiv ctx basis.workspace)
            basis.database =
          currentRoleEvent406Explicit adjusted.model adjusted.leafNamespace
            (fun key => adjusted.keyBytes key.val) adjusted.counter adjusted.routes adjusted.role
            adjusted.advice adjusted.outerFuel adjusted.innerFuel ∅ basis.database := by
          change currentRoleEvent406Explicit ctx.model ctx.leafNamespace
            (fun key => ctx.keyBytes key.val) ctx.counter ctx.routes ctx.role
            (currentFixedAdvice ctx blockCap fixed) ctx.outerFuel ctx.innerFuel ∅ basis.database = _
          rfl
        rw [specEventEq]
        exact Or.inl activeEvent
    | opening =>
        rcases roleFailureOnTrace with ⟨source, recovered, notFull, openingBad⟩
        have openingFailure :
            execution.opening ∈ SmzaRp04ChronologicalAlgebra.piopOpeningBadEvent
              ((relationModel currentDsl certificates).recoveredCandidate statement source.data)
              execution.matrix (SmzaRp05TracePrefixes.piopResponse messages.piop) :=
          openingBad
        have selectedStageRoleEvent := accepted_execution_selected_piop_failure_yields_role_event
          producer ns currentDsl statement pending nonce branch accepted completed claims fallback
          certificates bounded 28 (by decide) ∅ (by simp) wire transcript execution pcs
          producerSuccess verifierAccepted transcriptSuccess recordsCollisionFree
          adviceFamily messages earlierFixed source recovered .opening openingFailure
        let adjusted := { ctx with advice := currentFixedAdvice ctx blockCap fixed }
        have ctxRole : ctx.role = .piopOpening := rfl
        have adviceEq : adviceFamily .piopOpening = currentFixedAdvice ctx blockCap fixed := by
          change currentFixedEarlierAdviceFamily ctx blockCap fixed oracle ctx.role = _
          exact currentFixedEarlierAdviceFamily_active ctx blockCap fixed oracle
        have baseEvent : current406Base adjusted ∅ completed := by
          change currentRoleEvent406Explicit model ns ctx.keyBytes ctx.counter ctx.routes
            .piopOpening (currentFixedAdvice ctx blockCap fixed) 28 28 ∅ completed
          change currentPiopRoleEvent406 model ns ctx.keyBytes ctx.counter ctx.routes .opening
            (currentFixedAdvice ctx blockCap fixed) 28 28 ∅ completed
          rw [← adviceEq]
          exact selectedStageRoleEvent
        have activeEvent := (current406_base_merged_iff_active adjusted blockCap fixed
          basis.database ∅).mp baseEvent
        have specEventEq : event (currentAdviceEventSpec ctx blockCap fixed cap)
            (SmzaRp05ConditionedExecution.activeMemoryEquiv ctx basis.workspace)
            basis.database =
          currentRoleEvent406Explicit adjusted.model adjusted.leafNamespace
            (fun key => adjusted.keyBytes key.val) adjusted.counter adjusted.routes adjusted.role
            adjusted.advice adjusted.outerFuel adjusted.innerFuel ∅ basis.database := by
          change currentRoleEvent406Explicit ctx.model ctx.leafNamespace
            (fun key => ctx.keyBytes key.val) ctx.counter ctx.routes ctx.role
            (currentFixedAdvice ctx blockCap fixed) ctx.outerFuel ctx.innerFuel ∅ basis.database = _
          rfl
        rw [specEventEq]
        exact Or.inl activeEvent
  · exact Or.inr challengeClaims


end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopExtractionFailureEvent
