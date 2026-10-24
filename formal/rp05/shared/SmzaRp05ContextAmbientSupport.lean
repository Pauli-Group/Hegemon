import SmzaRp05ContextAmbientCoverage
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
namespace HegemonCrypto.SmallWood.SmzaRp05ContextAmbientSupport

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


open SmzaRp05ContextAmbientDecoder (ParsedContext fixedNamespaceContextProgram)
open SmzaRp05ContextAmbientCoverage (ambientXViewFailureRoleSelector)
open V8Smz9PiopReconstruction (points)
open SmzaRp05CurrentMaxAgreementRecovery (Position)
open SmzaRp05CurrentAcceptedXViewRoleCoverage (noWitnessRoleFailure)

def AmbientRoleEvidence (producer : Program ParsedContext)
    (ns : SmzaRp05LeafNamespace.Namespace) (fallback : RawDigest) (fuel : Nat)
    (role : Role)
    (database : Database (Key (fixedNamespaceContextProgram ns producer))
      (VectorOutput GroupCounter)) : Prop :=
  let actualProgram := fixedNamespaceContextProgram ns producer
  ∃ c : ParsedContext, let erasedRecords := eraseChallengeRecords (rawRecords
       (fun key => groupRepresentative (included actualProgram key))
       (vectorOutputBytes groupZero) database)
     let filteredRecords := oneStatementFilter (globalLeafStatement ns)
       c.statement.toBytes erasedRecords
     SmzaRecordedTracePath.RecordsCollisionFree filteredRecords ∧
     ∃ oracle : SmzaRp05ExecutableMerkleVerifier.Oracle,
      oracle = finiteGroupedDatabaseOracle actualProgram database fallback ∧
      ∃ transcript, producer.eval oracle = some c ∧
        (verifierProgram ns currentDsl c.statement c.pending c.nonce c.wire).eval oracle = some () ∧
        (SmzaRp05ExecutablePcsClosure.transcriptProgram ns currentDsl c.statement c.pending
          c.statement.toBytes (statementBindingWords c.statement) c.nonce c.wire).eval oracle =
          some transcript ∧
        ∃ execution : ExecutionStages ns currentDsl c.statement c.pending c.statement.toBytes
          (statementBindingWords c.statement) c.nonce c.wire oracle transcript,
        ∃ pcs : PcsStages ns execution.openingPending c.wire.hPiop
          (sameProofRows execution.middle.pcs execution.piop) execution.decs
          (List.ofFn fun j : Fin 6 => points execution.opening j)
          c.wire.salt c.statement.toBytes (statementBindingWords c.statement) c.wire.tapes
          c.wire.paths oracle execution.hashFpp execution.pcsPending,
        ∃ coordinates : Fin 38 → Position, ∃ query : Query, ∃ input : RawInput,
          StrictMono coordinates ∧ query.val = Finset.univ.image coordinates ∧
          (∀ j : Fin 38, (coordinates j).val = pcs.indexes.getD j.val 0) ∧
          (input, execution.hashFpp) ∈ filteredRecords ∧
          (input, execution.hashFpp) ∈ (pcs.hashProgram.record oracle).2 ∧
          CurrentDecoderOutcome
            (SmzaRp05CurrentRetainedQuerySupport.measuredDataTable ns filteredRecords
              fuel pcs.post.root)
            (SmzaRp05CurrentRetainedQuerySupport.measuredMaskTable ns filteredRecords
              fuel pcs.post.root)
            (responseRuleOfRawInputSelection (fun _ : Coefficients => input))
            (sampledCoefficients (gammaRows pcs.post)) pcs.heads
            (currentStageTails (sameProofRows execution.middle.pcs execution.piop))
            (fun opening => (List.ofFn fun j : Fin 6 => points execution.opening j).getD
              opening.val 0) query ∧
          CurrentNoWitnessLabelOutcome ns c.statement c.pending c.nonce c.wire oracle transcript
            execution pcs erasedRecords fuel input query ∧
          noWitnessRoleFailure role ns c.statement c.pending c.nonce c.wire oracle transcript
            execution pcs erasedRecords fuel input query

theorem selected_ambient_failure_role_replays_on_completion
    (producer : Program ParsedContext)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (fallback : RawDigest)
    (fuel : Nat)
    (ctx : Context (Key := Key
      (fixedNamespaceContextProgram ns producer))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (keyBytesExact : ∀ key, ctx.keyBytes key =
      SmzaRp05GroupedSuffix.groupRepresentative (included
        (fixedNamespaceContextProgram ns producer)
        key))
    (branch : Branches groupedDecode
      (fixedNamespaceContextProgram ns producer))
    (fixed : FixedTable ctx blockCap)
    (initial : ActiveState ctx blockCap)
    (basis : Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter) (ActiveMemory ctx))
    (challengeClaims : ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims ctx blockCap
        (encode (fixedNamespaceContextProgram ns producer)) groupedDecode
        (fixedNamespaceContextProgram ns producer)
        branch) basis.database)
    (selectorSupport : selectedRoleState ctx blockCap
      (encode (fixedNamespaceContextProgram ns producer)) groupedDecode
      (fixedNamespaceContextProgram ns producer)
      branch fixed initial
      (fun view _work => ambientXViewFailureRoleSelector producer ns fallback fuel ctx ctx.role branch view) basis ≠ 0) :
    AmbientRoleEvidence producer ns fallback fuel
      ctx.role (mergeFixedActive ctx blockCap fixed basis.database) := by
  classical
  let program := fixedNamespaceContextProgram ns producer
  let select := fun (view : XKey (nonchallengeRawKeySet ctx) →
      Option (VectorOutput GroupCounter)) (_work : Work (Counter := GroupCounter)
      (BaseWork := BaseWork)) =>
    ambientXViewFailureRoleSelector producer ns fallback
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
  have selectorAtView : ambientXViewFailureRoleSelector producer ns fallback fuel ctx ctx.role branch
      (activeXView ctx blockCap keys unrecognized basis.database) := by
    exact selectorOnActive
  dsimp only [ambientXViewFailureRoleSelector] at selectorAtView
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
  rcases completionEvidence with ⟨c, completionGood, completionEvidence⟩
  rcases completionEvidence with ⟨completionOracle, oracleEq, transcript,
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
      (fun output => verifierProgram ns currentDsl output.statement output.pending output.nonce output.wire)
      c producerOk member
    exact agrees raw included
  have verifierReadAgree : ∀ raw, (raw, leftOracle raw) ∈
      ((verifierProgram ns currentDsl c.statement c.pending c.nonce c.wire).record leftOracle).2 →
        leftOracle raw = rightOracle raw := by
    intro raw member
    have included := Program.bind_log_right leftOracle producer
      (fun output => verifierProgram ns currentDsl output.statement output.pending output.nonce output.wire)
      c producerOk member
    exact agrees raw included
  have producerEvalEq := eval_eq_of_agrees_on_left_reads producer leftOracle rightOracle
    producerReadAgree
  have producerRight : producer.eval rightOracle = some c :=
    producerEvalEq.symm.trans producerOk
  have verifierRecordEq := record_eq_of_agrees_on_left_reads
    (verifierProgram ns currentDsl c.statement c.pending c.nonce c.wire) leftOracle rightOracle
    (by
      intro raw member
      have included := Program.bind_log_right leftOracle producer
        (fun output => verifierProgram ns currentDsl output.statement output.pending output.nonce output.wire)
        c producerOk member
      exact agrees raw included)
  have verifierEvalEq := eval_eq_of_agrees_on_left_reads
    (verifierProgram ns currentDsl c.statement c.pending c.nonce c.wire) leftOracle rightOracle
    (by
      intro raw member
      have included := Program.bind_log_right leftOracle producer
        (fun output => verifierProgram ns currentDsl output.statement output.pending output.nonce output.wire)
        c producerOk member
      exact agrees raw included)
  have verifierRight : (verifierProgram ns currentDsl c.statement c.pending c.nonce c.wire).eval
      rightOracle = some () := verifierEvalEq.symm.trans verifierOk

  let executionRight := replay_execution_stages_of_verifier_record_eq ns currentDsl
    c.statement c.pending c.nonce c.wire leftOracle rightOracle transcript execution verifierRecordEq
  let pcsRight := replay_pcs_stages_of_verifier_record_eq ns currentDsl c.statement
    c.pending c.nonce c.wire leftOracle rightOracle transcript execution pcs verifierRecordEq
  have transcriptRight := execution_transcript_success ns currentDsl c.statement c.pending
    c.nonce c.wire rightOracle transcript executionRight
  let erasedRight := SmzaRp05ChallengeRecordErasure.eraseChallengeRecords
    (rawRecords
      (fun key => SmzaRp05GroupedSuffix.groupRepresentative (included program key))
      (vectorOutputBytes groupZero) merged)
  let filteredRight := SmzaRp04StatementRecordFilter.oneStatementFilter
    (SmzaRp05FilteredReadback.globalLeafStatement ns) c.statement.toBytes erasedRight
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
  have filteredEq := congrArg
    (SmzaRp04StatementRecordFilter.oneStatementFilter
      (SmzaRp05FilteredReadback.globalLeafStatement ns) c.statement.toBytes) erasedEq
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
  have labelOutcomeRight : CurrentNoWitnessLabelOutcome ns c.statement c.pending c.nonce c.wire
      rightOracle transcript executionRight pcsRight erasedRight fuel input query := by
    change CurrentNoWitnessLabelOutcome ns c.statement c.pending c.nonce c.wire
      leftOracle transcript execution pcs erasedRight fuel input query
    exact (congrArg (fun records => CurrentNoWitnessLabelOutcome ns c.statement c.pending
      c.nonce c.wire leftOracle transcript execution pcs records fuel input query)
      erasedEq).mp labelOutcome
  have roleFailureRight :
      SmzaRp05CurrentAcceptedXViewRoleCoverage.noWitnessRoleFailure ctx.role ns
        c.statement c.pending c.nonce c.wire rightOracle transcript executionRight pcsRight
        erasedRight fuel input query := by
    change SmzaRp05CurrentAcceptedXViewRoleCoverage.noWitnessRoleFailure ctx.role ns
      c.statement c.pending c.nonce c.wire leftOracle transcript execution pcs
      erasedRight fuel input query
    exact (congrArg (fun records =>
      SmzaRp05CurrentAcceptedXViewRoleCoverage.noWitnessRoleFailure ctx.role ns
        c.statement c.pending c.nonce c.wire leftOracle transcript execution pcs
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
      c.wire.hPiop (sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      c.wire.salt c.statement.toBytes (statementBindingWords c.statement) c.wire.tapes
      c.wire.paths leftOracle execution.hashFpp execution.pcsPending pcs
      execution.pcsExecuted raw (leftOracle raw) member
    have transcriptSuccess := execution_transcript_success ns currentDsl c.statement
      c.pending c.nonce c.wire leftOracle transcript execution
    have intoVerifier := execution_pcs_records_retained_in_verifier ns currentDsl
      c.statement c.pending c.nonce c.wire leftOracle transcript execution transcriptSuccess
    exact agrees raw (Program.bind_log_right leftOracle producer
      (fun output => verifierProgram ns currentDsl output.statement output.pending output.nonce output.wire)
      c producerOk (intoVerifier (raw, leftOracle raw) intoPcs))
  have hashProgramRight : pcsRight.hashProgram = pcs.hashProgram := rfl
  have hashFppRight : executionRight.hashFpp = execution.hashFpp := rfl
  have hashMemberRight : (input, executionRight.hashFpp) ∈
      (pcsRight.hashProgram.record rightOracle).2 := by
    rw [hashProgramRight, hashFppRight, ← hashRecordEq]
    exact hashMember
  dsimp only [AmbientRoleEvidence]
  exact ⟨c, filteredGoodRight, ⟨rightOracle, rfl, transcript, producerRight, verifierRight, transcriptRight,
    executionRight, pcsRight, coordinates, query, input, ordered, image, indexes,
    inputMemberRight, hashMemberRight, currentOutcomeRight, labelOutcomeRight,
    roleFailureRight⟩⟩

end FailureReplay
end
end HegemonCrypto.SmallWood.SmzaRp05ContextAmbientSupport
