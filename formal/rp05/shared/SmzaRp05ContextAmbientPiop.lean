import SmzaRp05ContextAmbientSampleSupport
import SmzaRp05AcceptedRoleLabels
import SmzaRp05AdaptiveRetainedAdviceTransport
import SmzaRp05CertifiedReplayScheduleFrames
import SmzaRp05ChallengeRecordErasure
import SmzaRp05Current406ActiveFiberEvent
import SmzaRp05Current406EventSpec
import SmzaRp05CurrentAcceptedCausalPayloadIdentity
import SmzaRp05CurrentAcceptedCausalPayloads
import SmzaRp05CurrentAcceptedDecsOutputBinding
import SmzaRp05CurrentAcceptedEarlierAdvice
import SmzaRp05CurrentAcceptedFilteredRoleTraces
import SmzaRp05CurrentAcceptedFixedEarlierPiopCells
import SmzaRp05CurrentAcceptedFixedEarlierReadback
import SmzaRp05CurrentAcceptedNonleafRoleReadback
import SmzaRp05CurrentAcceptedPiopCausalCoverage
import SmzaRp05CurrentAcceptedPiopFailureEvents
import SmzaRp05CurrentAcceptedPiopOutputBinding
import SmzaRp05CurrentAcceptedPiopRecordLift
import SmzaRp05CurrentAcceptedPiopRecordedOutputs
import SmzaRp05CurrentAcceptedPiopRoleCalls
import SmzaRp05CurrentAcceptedPiopStageEventCoverage
import SmzaRp05CurrentAcceptedPiopStageOutputs
import SmzaRp05CurrentAcceptedPiopStageReadback
import SmzaRp05CurrentAcceptedRoleQueryReadback
import SmzaRp05CurrentAcceptedStageReplay
import SmzaRp05CurrentAcceptedXViewRoleCoverage
import SmzaRp05CurrentAdviceDependentPhysicalMass
import SmzaRp05CurrentBranchOracleAgreement
import SmzaRp05CurrentCausalNonchallengeRetention
import SmzaRp05CurrentDecsGroupedTarget
import SmzaRp05CurrentExecutedEarlierAdvice
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentFixedAdviceDecsSource
import SmzaRp05CurrentFixedAdviceOpeningSource
import SmzaRp05CurrentFixedAdvicePiopSource
import SmzaRp05CurrentFixedEarlierAdvice
import SmzaRp05CurrentFullOrRoleExtraction
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentGroupedContext
import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05CurrentGroupedPiopDecoders
import SmzaRp05CurrentGroupedRoutes
import SmzaRp05CurrentGroupedVerifierReplay
import SmzaRp05CurrentNonchallengeRecordView
import SmzaRp05CurrentOpeningGroupIdentity
import SmzaRp05CurrentOpeningSelectedRetention
import SmzaRp05CurrentPiopRoleEvents
import SmzaRp05CurrentSelectedCurrentAdviceEventMass
import SmzaRp05CurrentSelectedXViewClaims
import SmzaRp05CurrentSelectedXViewRoleTransfer
import SmzaRp05ExecutableMerklePaths
import SmzaRp05ExecutablePcsClosureClean
import SmzaRp05ExecutablePcsClosureSampling
import SmzaRp05ExecutablePcsClosureStatement
import SmzaRp05GroupedSuffix
import SmzaRp05PhysicalHashFppRecordRetention
import SmzaRp05PhysicalPcsRecordRetention
import SmzaRp05PhysicalProgramBridge

/-! # Lift actual PIOP reads into one accepted grouped branch

These adapters start from the verifier/transcript program's real raw record,
then lift that read through the successful producer bind and the same
branch's record equation. They do not posit an answer-log call or a separate
database cell.
-/

set_option linter.unusedVariables false
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopRecordLiftAmbientPiop

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult rawLog answerLog)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFixedAdviceOpeningSource (verifier_record_pair_has_branch_answer)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentFiniteGroupedProgram (Key)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05RelationRefinement (RelationDsl)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)

noncomputable section
set_option autoImplicit false

private theorem verifier_member_lifts_to_program_record
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext)
    (ns : Namespace) (dsl : RelationDsl)
    (c : SmzaRp05ContextAmbientDecoder.ParsedContext)
    (oracle : Oracle)
    (producerSuccess : producer.eval oracle = some c)
    (input : RawInput) (digest : RawDigest)
    (member : (input, digest) ∈
      ((verifierProgram ns dsl c.statement c.pending c.nonce c.wire).record oracle).2) :
    (input, digest) ∈
      ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire).record oracle).2 := by
  exact Program.bind_log_right oracle producer
    (fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
    c producerSuccess member

/-- A real verifier-record pair becomes an answer-log pair of the accepted
producer/verifier branch. The branch equation is the only grouped-replay
bridge; successful producer evaluation identifies the same verifier run. -/
theorem verifier_record_pair_is_accepted_branch_answer
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext)
    (ns : Namespace) (dsl : RelationDsl)
    (c : SmzaRp05ContextAmbientDecoder.ParsedContext) (oracle : Oracle)
    (branch : Branches groupedDecode
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
    (recordEq :
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire).record oracle =
      (branchResult groupedDecode
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch,
       rawLog groupedDecode
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch))
    (producerSuccess : producer.eval oracle = some c)
    (input : RawInput) (digest : RawDigest)
    (member : (input, digest) ∈
      ((verifierProgram ns dsl c.statement c.pending c.nonce c.wire).record oracle).2) :
    ∃ output, (input, output) ∈ answerLog groupedDecode
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch ∧
      groupedDecode input output = digest := by
  have wholeMember : (input, digest) ∈
      ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire).record oracle).2 :=
    verifier_member_lifts_to_program_record producer ns dsl
      c oracle producerSuccess input digest member
  exact verifier_record_pair_has_branch_answer
    (Key := Key (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
    (program := producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
    branch oracle recordEq input digest wholeMember

/-- The transcript-level form used by PIOP samplers: lift an actual raw
transcript read first through the verifier continuation, then through the
successful producer and into the same accepted branch. -/
theorem transcript_record_pair_is_accepted_branch_answer
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext)
    (ns : Namespace) (dsl : RelationDsl)
    (c : SmzaRp05ContextAmbientDecoder.ParsedContext) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
    (transcriptSuccess :
      (SmzaRp05ExecutablePcsClosure.transcriptProgram ns dsl c.statement c.pending
        c.statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords c.statement)
        c.nonce c.wire).eval oracle = some transcript)
    (branch : Branches groupedDecode
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
    (recordEq :
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire).record oracle =
      (branchResult groupedDecode
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch,
       rawLog groupedDecode
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch))
    (producerSuccess : producer.eval oracle = some c)
    (input : RawInput) (digest : RawDigest)
    (member : (input, digest) ∈
      ((SmzaRp05ExecutablePcsClosure.transcriptProgram ns dsl c.statement c.pending
        c.statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords c.statement)
        c.nonce c.wire).record oracle).2) :
    ∃ output, (input, output) ∈ answerLog groupedDecode
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch ∧
      groupedDecode input output = digest := by
  have verifierMember : (input, digest) ∈
      ((verifierProgram ns dsl c.statement c.pending c.nonce c.wire).record oracle).2 := by
    exact Program.bind_log_left oracle
      (SmzaRp05ExecutablePcsClosure.transcriptProgram ns dsl c.statement c.pending
        c.statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords c.statement)
        c.nonce c.wire)
      (SmzaRp05ExecutableFinalVerifier.finalize c.wire.hPiop)
      transcript transcriptSuccess member
  exact verifier_record_pair_is_accepted_branch_answer producer ns dsl c oracle branch recordEq producerSuccess input digest verifierMember

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopRecordLiftAmbientPiop

/-! # Accepted PIOP calls with their recorded vectors

These same-run adapters expose both the accepted branch's actual answer-log
membership and the current decoder result on the same returned vector.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopRecordedOutputsAmbientPiop

open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult rawLog answerLog)
open SmzaRp05CurrentGroupedClaimRetention
  (groupedDecode actual_program_grouped_claims_replay_and_retain)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05ExecutablePcsClosure (ExecutionStages transcriptProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05RelationRefinement (RelationDsl GeneratedCertificates relationModel)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05GroupedSuffix (GroupCounter)
open SmzaRp05CurrentAcceptedPiopRecordLiftAmbientPiop
  (verifier_record_pair_is_accepted_branch_answer
   transcript_record_pair_is_accepted_branch_answer)
open SmzaRp05CurrentAcceptedPiopRoleCalls (execution_matrix_counter_zero_raw_call)
open SmzaRp05CurrentAcceptedPiopStageOutputs
  (actual_grouped_piop_matrix_is_stage_matrix
   actual_grouped_piop_opening_is_stage_opening)
open SmzaRp05CurrentOpeningSelectedRetention
  (successful_canonical_opening_retains_selected_nonce_call_in_verifier_record)
open SmzaRp05ExecutablePcsClosureSampling (execution_stages_clean_matrix)
open SmzaRp05ExecutablePcsClosureClean (pcs_stages_clean)
open V8SmzaOracleParser (RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp05PcsToFinalProgram (sameProofRows)
open SmzaRp04RawRoleSampling (actualPiopMatrixOutput actualPiopOpeningOutput)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000

private theorem branch_record_equation
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext)
    (ns : Namespace) (dsl : RelationDsl)
    (c : SmzaRp05ContextAmbientDecoder.ParsedContext)
    (branch : Branches groupedDecode
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
    (database : Database
      (Key (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys
          (encode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          groupedDecode
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers
          (encode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          groupedDecode
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch))
      database)
    (fallback : RawDigest) :
    let program := producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire
    let oracle := finiteGroupedDatabaseOracle program database fallback
    program.record oracle =
      (branchResult groupedDecode program branch,
       rawLog groupedDecode program branch) := by
  let program := producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire
  let oracle := finiteGroupedDatabaseOracle program database fallback
  exact (actual_program_grouped_claims_replay_and_retain program branch database claims fallback).1

/-- Return the actual answer-log pair for the successful matrix sampler's
counter-zero query, along with its exact same-run decoder result. -/
theorem accepted_matrix_call_and_vector
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext) (ns : Namespace) (dsl : RelationDsl)
    (c : SmzaRp05ContextAmbientDecoder.ParsedContext)
    (branch : Branches groupedDecode
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
    (database : Database
      (Key (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys
          (encode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          groupedDecode
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers
          (encode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          groupedDecode
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch))
      database)
    (fallback : RawDigest)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) = some c)
    (transcript : ReconstructedTranscript)
    (transcriptSuccess : (transcriptProgram ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire).eval
        (finiteGroupedDatabaseOracle
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
          database fallback) = some transcript)
    (execution : ExecutionStages ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) transcript)
    (pcs : PcsStages ns execution.openingPending c.wire.hPiop
      (sameProofRows execution.middle.pcs execution.piop) execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      c.wire.salt c.statement.toBytes (statementBindingWords c.statement) c.wire.tapes c.wire.paths
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) execution.hashFpp execution.pcsPending)
    (clean : transcript.pendingXofFailure = false)
    (certificates : GeneratedCertificates dsl)
    (bounded : ModelWithinProtocol (relationModel dsl certificates)) :
    ∃ output, (SmzaRp05ExecutableChallengeStage.counterInput
        HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain execution.hashFpp 0,
        output) ∈ answerLog groupedDecode
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch ∧
      actualPiopMatrixOutput
        (SmzaRp05CurrentGroupedRoutes.currentGroupedRoutes
          (relationModel dsl certificates) bounded c.statement).piopMatrix output =
        some execution.matrix := by
  let program := producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire
  let oracle := finiteGroupedDatabaseOracle program database fallback
  have recordEq := branch_record_equation producer ns dsl c branch database claims fallback
  have widthPositive : 0 < dsl.width c.statement := by
    simp [SmzaRp05RelationRefinement.RelationDsl.width,
      certificates.nonlinear.nonlinearCountExact]
  have finalClean : execution.finalPending = false := by
    have projected := congrArg ReconstructedTranscript.pendingXofFailure execution.reconstructed
    have eq : execution.finalPending = transcript.pendingXofFailure := by
      simpa [SmzaRp05ExecutableReconstruction.reconstruct] using projected
    exact eq.trans clean
  have rawCall := execution_matrix_counter_zero_raw_call ns dsl c.statement c.pending c.nonce c.wire
    oracle transcript execution pcs widthPositive finalClean
  let input := SmzaRp05ExecutableChallengeStage.counterInput
    HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain execution.hashFpp 0
  obtain ⟨output, recorded, _digestEq⟩ := transcript_record_pair_is_accepted_branch_answer
    producer ns dsl c oracle transcript transcriptSuccess branch
    recordEq producerSuccess input (oracle input) (by simpa [input] using rawCall)
  have decoded := actual_grouped_piop_matrix_is_stage_matrix program branch
    (input, output) recorded database claims fallback dsl certificates ns c.statement c.pending
    c.nonce c.wire transcript execution clean bounded rfl
  exact ⟨output, recorded, decoded⟩

/-- Return the selected opening attempt's actual branch answer-log vector.
The counter index and its bound are the values from the same executed scan. -/
theorem accepted_opening_call_and_vector
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext) (ns : Namespace) (dsl : RelationDsl)
    (c : SmzaRp05ContextAmbientDecoder.ParsedContext)
    (branch : Branches groupedDecode
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
    (database : Database
      (Key (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys
          (encode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          groupedDecode
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers
          (encode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          groupedDecode
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch))
      database)
    (fallback : RawDigest)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) = some c)
    (transcript : ReconstructedTranscript)
    (transcriptSuccess : (transcriptProgram ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire).eval
        (finiteGroupedDatabaseOracle
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
          database fallback) = some transcript)
    (execution : ExecutionStages ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) transcript)
    (pcs : PcsStages ns execution.openingPending c.wire.hPiop
      (sameProofRows execution.middle.pcs execution.piop) execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      c.wire.salt c.statement.toBytes (statementBindingWords c.statement) c.wire.tapes c.wire.paths
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) execution.hashFpp execution.pcsPending)
    (clean : transcript.pendingXofFailure = false)
    (certificates : GeneratedCertificates dsl)
    (bounded : ModelWithinProtocol (relationModel dsl certificates)) :
    ∃ counter output, counter < 5 ∧
      (SmzaRp05CurrentOpeningProgram.openingCounterInput c.wire.hPiop c.nonce.val counter,
        output) ∈ answerLog groupedDecode
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch ∧
      actualPiopOpeningOutput
        (SmzaRp05CurrentGroupedRoutes.currentGroupedRoutes
          (relationModel dsl certificates) bounded c.statement).piopOpening output =
        some execution.opening := by
  let program := producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire
  let oracle := finiteGroupedDatabaseOracle program database fallback
  have recordEq := branch_record_equation producer ns dsl c branch database claims fallback
  have matrixClean := execution_stages_clean_matrix ns dsl c.statement c.pending
    c.statement.toBytes (statementBindingWords c.statement) c.nonce c.wire oracle transcript execution clean
  have openingClean := pcs_stages_clean ns execution.openingPending c.wire.hPiop
    (sameProofRows execution.middle.pcs execution.piop) execution.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
    c.wire.salt c.statement.toBytes (statementBindingWords c.statement) c.wire.tapes c.wire.paths
    oracle execution.hashFpp execution.pcsPending pcs matrixClean.1
  obtain ⟨counter, counterBound, member⟩ :=
    successful_canonical_opening_retains_selected_nonce_call_in_verifier_record
      ns dsl c.statement c.pending c.nonce c.wire oracle transcript execution pcs openingClean.1
      transcriptSuccess
  have fitsGroup : counter < SmzaRp05GroupedSuffix.groupBlockCap := by
    rw [SmzaRp05GroupedSuffix.group_block_cap_eq]
    omega
  let groupCounter : GroupCounter := ⟨counter, fitsGroup⟩
  let input := SmzaRp05CurrentOpeningProgram.openingCounterInput c.wire.hPiop c.nonce.val counter
  obtain ⟨output, recorded, _digestEq⟩ := verifier_record_pair_is_accepted_branch_answer
    producer ns dsl c oracle branch recordEq producerSuccess
    input (oracle input)
    (by simpa only [input, SmzaRp05ExecutablePcsClosureStatement.verifierProgram] using member)
  have decoded := actual_grouped_piop_opening_is_stage_opening program branch
    (input, output) recorded database claims fallback dsl certificates ns c.statement c.pending
    c.nonce c.wire transcript execution pcs clean bounded groupCounter rfl
  exact ⟨counter, output, counterBound, recorded, decoded⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopRecordedOutputsAmbientPiop

/-! # Current grouped PIOP output binding

For an actual branch answer at a PIOP counter call, derive its canonical
grouped key, stored vector, and every-coordinate route from the executed
parser and same branch's claims. No parser receipt, database cell, or route
address is supplied independently.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopOutputBindingAmbientPiop

open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CanonicalBytes (Byte encodeLE)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram
  (Key encode included answer_log_group_keys_represented)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05CurrentGroupedPiopDecoders
  (piop_matrix_decoder_from_stored_group_cell piop_opening_decoder_from_stored_group_cell)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes
  currentGroupedRoutes_piopMatrix_val currentGroupedRoutes_piopOpening_val)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05CertifiedReplaySchedule (ordinary_counter_roundtrip)
open SmzaRp05CurrentOpeningGroupIdentity (opening_counter_call_group_address)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix GroupCounter groupBlockCap groupZero groupKeyOf
    groupEncode groupRepresentative groupAddress group_address_encode group_block_cap_eq)
open SmzaRp05CurrentGroupedRecordReadback (canonicalQueryCounterInput)
open SmzaRp05TracePrefixes (RelationModel)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaChallengeStageTargets (Role StageQuery parseStageQuery)
open SmzaRp05CurrentOpeningProgram (openingCounterInput)
open SmzaRp05ExecutableChallengeStage (counterInput)
open SmzaRp05CurrentExecutedPiopMatrixReadback (currentPiopMatrixVector)
open SmzaRp05CurrentExecutedOpeningOutput (currentOpeningVector)
open SmzaRp04RawRoleSampling (actualPiopMatrixOutput actualPiopOpeningOutput)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9RawCounterCompiler (digestCallCap)
open V8Smz9AdaptiveFiniteAccounting.Historical (piopOpenings)
open HegemonCrypto.SmallWoodTranscript (piopCoefficientDomain)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000

/-- A real counter-zero PIOP-matrix answer fixes the decoder over the actual
finite grouped database on the current route. -/
theorem actual_grouped_piop_matrix_route_output
    {Result : Type} (program : Program Result)
    (branch : SmzaRp05PhysicalAcceptedReplayLite.Branches groupedDecode program)
    (call : RawInput × VectorOutput GroupCounter)
    (recorded : call ∈ SmzaRp05PhysicalAcceptedReplayLite.answerLog groupedDecode program branch)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys (encode program) groupedDecode program branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers (encode program) groupedDecode program branch))
      database)
    (fallback : RawDigest) (model : RelationModel)
    (bounded : ModelWithinProtocol model)
    (statement : SmzaRp05StatementNamespace.Statement) (digest : RawDigest)
    (inputEq : call.1 = counterInput piopCoefficientDomain digest 0) :
    actualPiopMatrixOutput (currentGroupedRoutes model bounded statement).piopMatrix call.2 =
      actualPiopMatrixOutput (Equiv.refl (Fin (digestCallCap (5 * model.width statement))))
        (currentPiopMatrixVector
          (finiteGroupedDatabaseOracle program database fallback) digest
          (model.width statement)) := by
  let query : StageQuery := ⟨.piopMatrix, digest, 0, 0⟩
  let leading : RawInput :=
    encodeLE 8 V8SmzaOracleParser.profileDomain.length ++
      V8SmzaOracleParser.profileDomain ++ encodeLE 8 piopCoefficientDomain.length ++
      piopCoefficientDomain ++ encodeLE 8 8 ++ List.ofFn digest
  let zeroCounter : Fin (2 ^ 64) := ⟨0, by norm_num⟩
  have parsedZero : parseStageQuery (leading ++ encodeLE 8 0) = some query := by
    change parseStageQuery (counterInput piopCoefficientDomain digest 0) = _
    simpa only [SmzaChallengeStageTargets.roleDomain,
      SmzaRp05ExecutableChallengeStage.counterInput, zeroCounter, Fin.val_mk, query] using
      ordinary_counter_roundtrip .piopMatrix (by decide) digest zeroCounter
  let rolePrefix : CanonicalRolePrefix :=
    ⟨.piopMatrix, leading, ⟨query, parsedZero, rfl⟩⟩
  have encoded : groupEncode (rolePrefix, groupZero) =
      counterInput piopCoefficientDomain digest 0 := by
    change leading ++ encodeLE 8 0 = _
    rfl
  have represented := answer_log_group_keys_represented
    groupedDecode program branch call recorded
  have keyIdentity : included program (encode program call.1) = Sum.inl rolePrefix := by
    calc
      included program (encode program call.1) = groupKeyOf call.1 := represented
      _ = Sum.inl rolePrefix := by
        change (groupAddress call.1).1 = Sum.inl rolePrefix
        rw [inputEq, ← encoded]
        exact congrArg Prod.fst (group_address_encode rolePrefix groupZero)
  have representativeParsed :
      parseStageQuery (groupRepresentative (Sum.inl rolePrefix)) = some query := by
    simpa only [groupRepresentative, groupEncode, rolePrefix, groupZero,
      V8Smz9CoherentVectorMerkle.canonicalRepresentative,
      V8Smz9RawCounterCompiler.boundedCounterInput,
      V8Smz9RawCounterCompiler.counterInput, Fin.val_mk] using parsedZero
  have parsed : parseStageQuery
      (groupRepresentative (included program (encode program call.1))) = some query := by
    rw [keyIdentity]
    exact representativeParsed
  obtain ⟨rolePrefix', keyIdentity', _, allCoordinates, _, stored, _, _⟩ :=
    current_actual_grouped_role_call_readback program branch call recorded database claims
      fallback .piopMatrix query parsed rfl rfl
  have counterAddress : ∀ index : Fin (digestCallCap (5 * model.width statement)),
      counterInput piopCoefficientDomain digest index.val =
        groupEncode (rolePrefix', (currentGroupedRoutes model bounded statement).piopMatrix index) := by
    intro index
    have coordinate := allCoordinates
      ((currentGroupedRoutes model bounded statement).piopMatrix index)
    have routeValue := currentGroupedRoutes_piopMatrix_val model bounded statement index
    rw [routeValue] at coordinate
    calc
      counterInput piopCoefficientDomain digest index.val =
          canonicalQueryCounterInput query index.val := by
        simp only [canonicalQueryCounterInput, query,
          SmzaChallengeStageTargets.roleDomain,
          HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain]
      _ = groupEncode (rolePrefix', (currentGroupedRoutes model bounded statement).piopMatrix index) :=
        coordinate.symm
  exact piop_matrix_decoder_from_stored_group_cell program database fallback
    (encode program call.1) rolePrefix' keyIdentity' call.2 stored digest
    (model.width statement) (currentGroupedRoutes model bounded statement).piopMatrix
    counterAddress

/-- One actual opening-counter answer fixes all six coordinates at that
nonce's own grouped prefix; it does not identify other nonce cells. -/
theorem actual_grouped_piop_opening_route_output
    {Result : Type} (program : Program Result)
    (branch : SmzaRp05PhysicalAcceptedReplayLite.Branches groupedDecode program)
    (call : RawInput × VectorOutput GroupCounter)
    (recorded : call ∈ SmzaRp05PhysicalAcceptedReplayLite.answerLog groupedDecode program branch)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys (encode program) groupedDecode program branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers (encode program) groupedDecode program branch))
      database)
    (fallback : RawDigest) (model : RelationModel)
    (bounded : ModelWithinProtocol model)
    (statement : SmzaRp05StatementNamespace.Statement) (digest : RawDigest)
    (nonce : Nat) (nonceBound : nonce < 2 ^ 32) (counter : GroupCounter)
    (inputEq : call.1 = openingCounterInput digest nonce counter.val) :
    actualPiopOpeningOutput (currentGroupedRoutes model bounded statement).piopOpening call.2 =
      actualPiopOpeningOutput (Equiv.refl (Fin (digestCallCap piopOpenings)))
        (currentOpeningVector
          (finiteGroupedDatabaseOracle program database fallback) digest nonce) := by
  obtain ⟨rolePrefix, addressEq, parsedZero, encoded⟩ :=
    opening_counter_call_group_address digest nonce nonceBound counter
  have represented := answer_log_group_keys_represented
    groupedDecode program branch call recorded
  have keyIdentity : included program (encode program call.1) = Sum.inl rolePrefix := by
    calc
      included program (encode program call.1) = groupKeyOf call.1 := represented
      _ = Sum.inl rolePrefix := by
        change (groupAddress call.1).1 = Sum.inl rolePrefix
        rw [inputEq, ← encoded]
        exact congrArg Prod.fst (group_address_encode rolePrefix counter)
  let query : StageQuery := ⟨.piopOpening, digest, nonce, 0⟩
  have representativeParsed :
      parseStageQuery (groupRepresentative (Sum.inl rolePrefix)) = some query := by
    simpa only [query] using parsedZero
  have parsed : parseStageQuery
      (groupRepresentative (included program (encode program call.1))) = some query := by
    rw [keyIdentity]
    exact representativeParsed
  obtain ⟨rolePrefix', keyIdentity', _, allCoordinates, _, stored, _, _⟩ :=
    current_actual_grouped_role_call_readback program branch call recorded database claims
      fallback .piopOpening query parsed rfl rfl
  have counterAddress : ∀ index : Fin (digestCallCap piopOpenings),
      openingCounterInput digest nonce index.val =
        groupEncode (rolePrefix', (currentGroupedRoutes model bounded statement).piopOpening index) := by
    intro index
    have coordinate := allCoordinates
      ((currentGroupedRoutes model bounded statement).piopOpening index)
    have routeValue := currentGroupedRoutes_piopOpening_val model bounded statement index
    rw [routeValue] at coordinate
    calc
      openingCounterInput digest nonce index.val =
          canonicalQueryCounterInput query index.val := by
        simp [canonicalQueryCounterInput, query]
      _ = groupEncode (rolePrefix', (currentGroupedRoutes model bounded statement).piopOpening index) :=
        coordinate.symm
  exact piop_opening_decoder_from_stored_group_cell program database fallback
    (encode program call.1) rolePrefix' keyIdentity' call.2 stored digest nonce
    (currentGroupedRoutes model bounded statement).piopOpening counterAddress

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopOutputBindingAmbientPiop

/-! # Same-run fixed PIOP earlier-cell readback

The two PIOP-selected advice families retain their actual verifier branch.
Fixed DECS cells use its recorded DECS matrix call; the opening-role PIOP
matrix cell uses the recorded PIOP matrix sampler call. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFixedEarlierPiopCellsAmbientPiop

open scoped Classical
open HegemonCrypto.CanonicalBytes (Byte encodeLE)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.CmsCompressedOracle (Basis)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ConditionedExecution
  (FixedTable ActiveMemory fixedFiberToActive otherRoleTransform)
open SmzaRp05CurrentFixedEarlierAdvice
  (currentFixedAdvice currentFixedVectorDecodedAt)
open SmzaRp05CurrentAcceptedFixedEarlierReadback
  (currentFixedEarlierAdviceFamily currentFixedEarlierAdviceFamily_active
    currentFixedEarlierAdviceFamily_other)
open SmzaRp05CurrentFixedAdviceDecsSource
  (current_decs_fixed_advice_matches_same_branch_source)
open SmzaRp05CurrentFixedAdvicePiopSource
  (current_piop_matrix_fixed_advice_matches_same_branch_source)
open SmzaRp05CurrentAcceptedDecsOutputBindingAmbient (same_stage_decs_counter_zero_decodes)
open SmzaRp05CurrentDecsGroupedTarget (recorded_decs_call_has_grouped_target)
open SmzaRp05CurrentAcceptedPiopRecordedOutputsAmbientPiop (accepted_matrix_call_and_vector)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes)
open SmzaRp05AcceptedRoleLabels (EarlierReadback CausalPayloads)
open SmzaRp05CurrentExecutedEarlierAdvice (currentOracleAllAdvice currentOracleDecodedAt)
open SmzaRp05CurrentAdaptiveExecution (Context CmsState)
open SmzaRp05CurrentFixedAdviceOpeningSource (verifier_record_pair_has_branch_answer)
open SmzaRp05CurrentGroupedClaimRetention
  (groupedDecode actual_program_grouped_claims_replay_and_retain)
open SmzaRp05CurrentFiniteGroupedProgram
  (Key encode included answer_log_group_keys_represented)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult answerLog)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutablePcsClosure
  (ExecutionStages transcriptProgram)
open SmzaRp05ExecutablePcsClosureStatement (statementBindingWords verifierProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05RelationRefinement (RelationDsl GeneratedCertificates relationModel)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative groupZero)
open SmzaChallengeStageTargets (Role StageQuery parseStageQuery)
open SmzaRoleDomainConditioning (ActiveKey)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp05ExecutableChallengeStage (counterInput)
open SmzaRp05CurrentFiniteGroupedProgram (included encode)
open SmzaRp05CurrentAcceptedRoleTraceReadback (accepted_decs_matrix_counter_parses)
open SmzaRp05CurrentAcceptedEarlierAdvice
  (accepted_execution_supplies_earlier_advice_of_nonchallenge_retention)
open SmzaRp05CurrentAcceptedDecsOutputBindingAmbient (same_stage_decs_counter_zero_decodes)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes_decsMatrix_val)
open SmzaRp05CurrentGroupedContext (current_grouped_context_key_injective)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes_piopMatrix_val)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix groupKeyOf groupEncode groupAddress group_address_encode)
open SmzaRp05CertifiedReplaySchedule (ordinary_counter_roundtrip)
open SmzaRp05ExecutableChallengeStage (counterInput)
open HegemonCrypto.SmallWoodTranscript (decsCoefficientDomain piopCoefficientDomain)
open SmzaRp05PcsToFinalProgram (sameProofRows)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 16000
set_option maxHeartbeats 1500000
set_option linter.unusedSectionVars false
set_option linter.unusedVariables false

private def fixedEarlierFamilyAtModel
    {Key Counter BaseWork : Type} [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (fixed : FixedTable ctx blockCap) (oracle : Oracle)
    (statement : SmzaRp05StatementNamespace.Statement)
    (model : RelationModel) (modelEq : ctx.model = model) :
    (selected : Role) → SmzaRp05TracePrefixes.EarlierTables model statement selected :=
  fun selected => modelEq ▸
    currentFixedEarlierAdviceFamily ctx blockCap fixed oracle selected statement

/-- A counter-zero PIOP matrix answer in the accepted grouped branch has the
canonical parser representative required by fixed-advice readback. -/
private theorem matrix_call_representative_parses
    {Result : Type} (program : Program Result)
    (branch : Branches groupedDecode program)
    (call : RawInput × VectorOutput GroupCounter)
    (recorded : call ∈ answerLog groupedDecode program branch)
    (digest : RawDigest)
    (inputEq : call.1 = counterInput piopCoefficientDomain digest 0) :
    parseStageQuery (groupRepresentative
      (included program (encode program call.1))) =
        some (⟨.piopMatrix, digest, 0, 0⟩ : StageQuery) := by
  let query : StageQuery := ⟨.piopMatrix, digest, 0, 0⟩
  let leading : RawInput :=
    encodeLE 8 V8SmzaOracleParser.profileDomain.length ++
      V8SmzaOracleParser.profileDomain ++ encodeLE 8 piopCoefficientDomain.length ++
      piopCoefficientDomain ++ encodeLE 8 8 ++ List.ofFn digest
  let zeroCounter : Fin (2 ^ 64) := ⟨0, by norm_num⟩
  have parsedZero : parseStageQuery (leading ++ encodeLE 8 0) = some query := by
    change parseStageQuery (counterInput piopCoefficientDomain digest 0) = _
    simpa only [SmzaChallengeStageTargets.roleDomain,
      SmzaRp05ExecutableChallengeStage.counterInput, zeroCounter, Fin.val_mk, query] using
      ordinary_counter_roundtrip .piopMatrix (by decide) digest zeroCounter
  let rolePrefix : CanonicalRolePrefix :=
    ⟨.piopMatrix, leading, ⟨query, parsedZero, rfl⟩⟩
  have encoded : groupEncode (rolePrefix, groupZero) =
      counterInput piopCoefficientDomain digest 0 := by
    change leading ++ encodeLE 8 0 = _
    rfl
  have represented := answer_log_group_keys_represented
    groupedDecode program branch call recorded
  have keyIdentity : included program (encode program call.1) = Sum.inl rolePrefix := by
    calc
      included program (encode program call.1) = groupKeyOf call.1 := represented
      _ = Sum.inl rolePrefix := by
        change (groupAddress call.1).1 = Sum.inl rolePrefix
        rw [inputEq, ← encoded]
        exact congrArg Prod.fst (group_address_encode rolePrefix groupZero)
  have representativeParsed : parseStageQuery (groupRepresentative (Sum.inl rolePrefix)) =
      some query := by
    simpa only [groupRepresentative, groupEncode, rolePrefix, groupZero,
      V8Smz9CoherentVectorMerkle.canonicalRepresentative,
      V8Smz9RawCounterCompiler.boundedCounterInput,
      V8Smz9RawCounterCompiler.counterInput, Fin.val_mk] using parsedZero
  rw [keyIdentity]
  exact representativeParsed

-- The public wrappers below share one same-run proof. The role premise keeps
-- the fixed table active at a PIOP role; no table is supplied for a different
-- execution or verifier branch.
theorem same_stage_fixed_piop_earlier_readback
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext)
    (ns : Namespace) (dsl : RelationDsl)
    (c : SmzaRp05ContextAmbientDecoder.ParsedContext)
    (branch : Branches groupedDecode
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
    (_accepted : branchResult groupedDecode
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
      branch = some ())
    (database : Database (Key (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys
          (encode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          groupedDecode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers
          (encode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          groupedDecode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch))
      database)
    [Fintype RawDigest] (fallback : RawDigest)
    (certificates : GeneratedCertificates dsl)
    (boundedModel : ModelWithinProtocol (relationModel dsl certificates))
    (role : Role) (roleIsPiop : role = .piopMatrix ∨ role = .piopOpening)
    (advice : AllEarlierTables (relationModel dsl certificates) role)
    (outerFuel innerFuel : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (blockCap : Role → Nat)
    (dummy : ActiveKey
      (currentGroupedContext (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
        authorizedOf).role blockCap
      (currentGroupedContext (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
        authorizedOf).keyBytes)
    (fixed : FixedTable
      (currentGroupedContext (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
        authorizedOf) blockCap)
    (state : CmsState
      (Key := Key (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (basis : Basis
      (ActiveKey
        (currentGroupedContext (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
          (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
          authorizedOf).role blockCap
        (currentGroupedContext (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
          (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
          authorizedOf).keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (ActiveMemory (currentGroupedContext (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
        authorizedOf)))
    (nonzero : fixedFiberToActive
      (currentGroupedContext (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
        authorizedOf) blockCap dummy fixed
      (otherRoleTransform
        (currentGroupedContext (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
          (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
          authorizedOf) blockCap
        (SmzaRp05PhysicalAcceptedReplayLite.physicalRun
          (encode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          groupedDecode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
          branch state)) basis ≠ 0)
    (positiveDecsMatrixCap : 0 < blockCap .decsMatrix)
    (positivePiopMatrixCap : 0 < blockCap .piopMatrix)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) = some c)
    (verifierAccepted : (verifierProgram ns dsl c.statement c.pending c.nonce c.wire).eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) = some ())
    (transcript : ReconstructedTranscript)
    (transcriptSuccess : (transcriptProgram ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire).eval
        (finiteGroupedDatabaseOracle
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
          database fallback) = some transcript)
    (execution : ExecutionStages ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) transcript)
    (pcs : PcsStages ns execution.openingPending c.wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      c.wire.salt c.statement.toBytes (statementBindingWords c.statement) c.wire.tapes c.wire.paths
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) execution.hashFpp execution.pcsPending)
    {leafNs : Namespace} {trace : SmzaRp05TracePrefixes.Trace}
    (messages : CausalPayloads leafNs trace)
    (_decsDigest : V8SmzaOracleParser.digestAt messages.decs.bytes 0 = c.wire.hPiop)
    (fppDigest : V8SmzaOracleParser.digestAt messages.fpp.bytes 0 = pcs.post.root)
    (piopDigest : V8SmzaOracleParser.digestAt messages.piop.bytes 0 = execution.hashFpp)
    (oracleEarlier : EarlierReadback
      (relationModel dsl certificates) c.statement
      (fun selected => currentOracleAllAdvice (relationModel dsl certificates)
        (finiteGroupedDatabaseOracle
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
          database fallback) selected c.statement)
      messages
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
      execution.matrix execution.opening) :
    EarlierReadback (relationModel dsl certificates) c.statement
      (fixedEarlierFamilyAtModel
        (currentGroupedContext (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
          (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
          authorizedOf)
        blockCap fixed
        (finiteGroupedDatabaseOracle
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
          database fallback)
        c.statement (relationModel dsl certificates) (by rfl))
      messages
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
      execution.matrix execution.opening := by
  rcases roleIsPiop with rfl | rfl
  · let role : Role := Role.piopMatrix
    classical
    let model := relationModel dsl certificates
    let program := producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire
    let oracle := finiteGroupedDatabaseOracle
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
      database fallback
    let ctx := currentGroupedContext program model boundedModel ns role advice
      outerFuel innerFuel authorizedOf
    have ctxModel : ctx.model = model := rfl
    have ctxRole : ctx.role = role := rfl
    have decsCall := same_stage_decs_counter_zero_decodes producer ns dsl c branch database claims fallback model boundedModel transcript execution
      producerSuccess pcs verifierAccepted transcriptSuccess
    obtain ⟨_branchOk, decsVector, decsRecorded, _actualDecs⟩ := decsCall
    let decsInput := counterInput decsCoefficientDomain pcs.post.root 0
    have decsCallRecorded : (decsInput, decsVector) ∈ answerLog groupedDecode program branch := by
      simpa only [decsInput] using decsRecorded
    let decsQuery : StageQuery := ⟨.decsMatrix, pcs.post.root, 0, 0⟩
    have decsTarget := recorded_decs_call_has_grouped_target program branch
      (decsInput, decsVector) decsCallRecorded pcs.post.root ⟨0, by decide⟩ rfl
    rcases decsTarget with ⟨_decsPrefix, decsKey, decsRepresentative, _decsTarget⟩
    have decsParsed : parseStageQuery (ctx.keyBytes (encode program decsInput)) =
        some decsQuery := by
      change parseStageQuery (groupRepresentative (included program (encode program decsInput))) = _
      rw [decsKey]
      simpa only [decsQuery] using decsRepresentative
    have fixedDecs := current_decs_fixed_advice_matches_same_branch_source
      program model boundedModel ns role advice outerFuel innerFuel authorizedOf blockCap dummy
      fixed branch state basis nonzero database fallback claims (decsInput, decsVector)
      decsCallRecorded c.statement decsQuery decsParsed rfl
      (by simp [role])
      positiveDecsMatrixCap rfl
    have fixedDecsCell : currentFixedAdvice ctx blockCap fixed c.statement .decsMatrix
        (by
          change SmzaRp05TracePrefixes.roleOrder .decsMatrix <
            SmzaRp05TracePrefixes.roleOrder .piopMatrix
          decide)
        (V8SmzaOracleParser.digestAt messages.fpp.bytes 0) =
          some (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
            (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) := by
      rw [fppDigest]
      change currentFixedVectorDecodedAt ctx blockCap fixed c.statement .decsMatrix
        pcs.post.root 0 = _
      rw [fixedDecs]
      change currentOracleDecodedAt model oracle c.statement .decsMatrix pcs.post.root = _
      simpa only [model, currentOracleAllAdvice, currentOracleDecodedAt, fppDigest] using
        oracleEarlier.sampleCoefficients
    obtain ⟨acceptedTranscript, acceptedTranscriptSuccess, transcriptClean,
        _finalEq, _finalCall⟩ :=
      SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl
        c.statement c.pending c.statement.toBytes (statementBindingWords c.statement) c.nonce c.wire oracle
        verifierAccepted
    have sameTranscript : acceptedTranscript = transcript :=
      Option.some.inj (acceptedTranscriptSuccess.symm.trans transcriptSuccess)
    have suppliedTranscriptClean : transcript.pendingXofFailure = false := by
      rw [← sameTranscript]
      exact transcriptClean
    let piopInput := counterInput piopCoefficientDomain execution.hashFpp 0
    obtain ⟨piopVector, piopRecorded, _actualMatrix⟩ :=
      accepted_matrix_call_and_vector producer ns dsl c branch database
        claims fallback producerSuccess transcript transcriptSuccess execution pcs
        suppliedTranscriptClean certificates boundedModel
    let piopCall : RawInput × VectorOutput GroupCounter := (piopInput, piopVector)
    have piopCallRecorded : piopCall ∈ answerLog groupedDecode program branch := by
      simpa only [piopCall, piopInput] using piopRecorded
    have piopParsedRep := matrix_call_representative_parses program branch piopCall
      piopCallRecorded execution.hashFpp rfl
    have piopParsed : parseStageQuery (ctx.keyBytes (encode program piopInput)) =
        some (⟨.piopMatrix, execution.hashFpp, 0, 0⟩ : StageQuery) := by
      change parseStageQuery (groupRepresentative (included program (encode program piopInput))) = _
      simpa only [piopCall, piopInput] using piopParsedRep
    let adviceFamily := fixedEarlierFamilyAtModel ctx blockCap fixed oracle c.statement model ctxModel
    let adviceFamily := fixedEarlierFamilyAtModel ctx blockCap fixed oracle c.statement model ctxModel
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · have sameAdvice : adviceFamily .piopMatrix =
          currentFixedAdvice ctx blockCap fixed c.statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        change currentFixedEarlierAdviceFamily ctx blockCap fixed oracle ctx.role c.statement = _
        rw [currentFixedEarlierAdviceFamily_active]
      change adviceFamily .piopMatrix .decsMatrix _ _ = _
      rw [sameAdvice]
      exact fixedDecsCell
    · have notActive : .piopOpening ≠ ctx.role := by rw [ctxRole]; decide
      have sameAdvice : adviceFamily .piopOpening =
          currentOracleAllAdvice model oracle .piopOpening c.statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
          .piopOpening notActive]
        rfl
      change adviceFamily .piopOpening .decsMatrix _ _ = _
      rw [sameAdvice]
      exact oracleEarlier.openingCoefficients
    · have notActive : .piopOpening ≠ ctx.role := by rw [ctxRole]; decide
      have sameAdvice : adviceFamily .piopOpening =
          currentOracleAllAdvice model oracle .piopOpening c.statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
          .piopOpening notActive]
        rfl
      change adviceFamily .piopOpening .piopMatrix _ _ = _
      rw [sameAdvice]
      exact oracleEarlier.openingMatrix
    · have notActive : .decsSample ≠ ctx.role := by rw [ctxRole]; decide
      have sameAdvice : adviceFamily .decsSample =
          currentOracleAllAdvice model oracle .decsSample c.statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
          .decsSample notActive]
        rfl
      change adviceFamily .decsSample .decsMatrix _ _ = _
      rw [sameAdvice]
      exact oracleEarlier.sampleCoefficients
    · have notActive : .decsSample ≠ ctx.role := by rw [ctxRole]; decide
      have sameAdvice : adviceFamily .decsSample =
          currentOracleAllAdvice model oracle .decsSample c.statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
          .decsSample notActive]
        rfl
      change adviceFamily .decsSample .piopOpening _ _ = _
      rw [sameAdvice]
      exact oracleEarlier.sampleOpening
  · let role : Role := Role.piopOpening
    classical
    let model := relationModel dsl certificates
    let program := producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire
    let oracle := finiteGroupedDatabaseOracle
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
      database fallback
    let ctx := currentGroupedContext program model boundedModel ns role advice
      outerFuel innerFuel authorizedOf
    have ctxModel : ctx.model = model := rfl
    have ctxRole : ctx.role = role := rfl
    have decsCall := same_stage_decs_counter_zero_decodes producer ns dsl c branch database claims fallback model boundedModel transcript execution
      producerSuccess pcs verifierAccepted transcriptSuccess
    obtain ⟨_branchOk, decsVector, decsRecorded, _actualDecs⟩ := decsCall
    let decsInput := counterInput decsCoefficientDomain pcs.post.root 0
    have decsCallRecorded : (decsInput, decsVector) ∈ answerLog groupedDecode program branch := by
      simpa only [decsInput] using decsRecorded
    let decsQuery : StageQuery := ⟨.decsMatrix, pcs.post.root, 0, 0⟩
    have decsTarget := recorded_decs_call_has_grouped_target program branch
      (decsInput, decsVector) decsCallRecorded pcs.post.root ⟨0, by decide⟩ rfl
    rcases decsTarget with ⟨_decsPrefix, decsKey, decsRepresentative, _decsTarget⟩
    have decsParsed : parseStageQuery (ctx.keyBytes (encode program decsInput)) =
        some decsQuery := by
      change parseStageQuery (groupRepresentative (included program (encode program decsInput))) = _
      rw [decsKey]
      simpa only [decsQuery] using decsRepresentative
    have fixedDecs := current_decs_fixed_advice_matches_same_branch_source
      program model boundedModel ns role advice outerFuel innerFuel authorizedOf blockCap dummy
      fixed branch state basis nonzero database fallback claims (decsInput, decsVector)
      decsCallRecorded c.statement decsQuery decsParsed rfl
      (by simp [role])
      positiveDecsMatrixCap rfl
    have fixedDecsCell : currentFixedAdvice ctx blockCap fixed c.statement .decsMatrix
        (by
          change SmzaRp05TracePrefixes.roleOrder .decsMatrix <
            SmzaRp05TracePrefixes.roleOrder .piopOpening
          decide)
        (V8SmzaOracleParser.digestAt messages.fpp.bytes 0) =
          some (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
            (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) := by
      rw [fppDigest]
      change currentFixedVectorDecodedAt ctx blockCap fixed c.statement .decsMatrix
        pcs.post.root 0 = _
      rw [fixedDecs]
      change currentOracleDecodedAt model oracle c.statement .decsMatrix pcs.post.root = _
      simpa only [model, currentOracleAllAdvice, currentOracleDecodedAt, fppDigest] using
        oracleEarlier.sampleCoefficients
    obtain ⟨acceptedTranscript, acceptedTranscriptSuccess, transcriptClean,
        _finalEq, _finalCall⟩ :=
      SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl
        c.statement c.pending c.statement.toBytes (statementBindingWords c.statement) c.nonce c.wire oracle
        verifierAccepted
    have sameTranscript : acceptedTranscript = transcript :=
      Option.some.inj (acceptedTranscriptSuccess.symm.trans transcriptSuccess)
    have suppliedTranscriptClean : transcript.pendingXofFailure = false := by
      rw [← sameTranscript]
      exact transcriptClean
    let piopInput := counterInput piopCoefficientDomain execution.hashFpp 0
    obtain ⟨piopVector, piopRecorded, _actualMatrix⟩ :=
      accepted_matrix_call_and_vector producer ns dsl c branch database
        claims fallback producerSuccess transcript transcriptSuccess execution pcs
        suppliedTranscriptClean certificates boundedModel
    let piopCall : RawInput × VectorOutput GroupCounter := (piopInput, piopVector)
    have piopCallRecorded : piopCall ∈ answerLog groupedDecode program branch := by
      simpa only [piopCall, piopInput] using piopRecorded
    have piopParsedRep := matrix_call_representative_parses program branch piopCall
      piopCallRecorded execution.hashFpp rfl
    have piopParsed : parseStageQuery (ctx.keyBytes (encode program piopInput)) =
        some (⟨.piopMatrix, execution.hashFpp, 0, 0⟩ : StageQuery) := by
      change parseStageQuery (groupRepresentative (included program (encode program piopInput))) = _
      simpa only [piopCall, piopInput] using piopParsedRep
    let adviceFamily := fixedEarlierFamilyAtModel ctx blockCap fixed oracle c.statement model ctxModel
    let adviceFamily := fixedEarlierFamilyAtModel ctx blockCap fixed oracle c.statement model ctxModel
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · have notActive : .piopMatrix ≠ ctx.role := by rw [ctxRole]; decide
      have sameAdvice : adviceFamily .piopMatrix =
          currentOracleAllAdvice model oracle .piopMatrix c.statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
          .piopMatrix notActive]
        rfl
      change adviceFamily .piopMatrix .decsMatrix _ _ = _
      rw [sameAdvice]
      exact oracleEarlier.matrixCoefficients
    · have sameAdvice : adviceFamily .piopOpening =
          currentFixedAdvice ctx blockCap fixed c.statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        change currentFixedEarlierAdviceFamily ctx blockCap fixed oracle ctx.role c.statement = _
        rw [currentFixedEarlierAdviceFamily_active]
      change adviceFamily .piopOpening .decsMatrix _ _ = _
      rw [sameAdvice]
      exact fixedDecsCell
    · have sameAdvice : adviceFamily .piopOpening =
          currentFixedAdvice ctx blockCap fixed c.statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        change currentFixedEarlierAdviceFamily ctx blockCap fixed oracle ctx.role c.statement = _
        rw [currentFixedEarlierAdviceFamily_active]
      have oracleOpeningMatrix := oracleEarlier.openingMatrix
      rw [piopDigest] at oracleOpeningMatrix
      have fixedPiopMatrix := current_piop_matrix_fixed_advice_matches_same_branch_source
        program model boundedModel ns role advice outerFuel innerFuel authorizedOf blockCap dummy
        fixed branch state basis nonzero database fallback claims piopCall piopCallRecorded
        c.statement ⟨.piopMatrix, execution.hashFpp, 0, 0⟩ piopParsed rfl
        (by
          change Role.piopMatrix ≠ Role.piopOpening
          decide) positivePiopMatrixCap rfl
      have fixedPiopMatrixCell : currentFixedAdvice ctx blockCap fixed c.statement .piopMatrix
          (by
            change SmzaRp05TracePrefixes.roleOrder .piopMatrix <
              SmzaRp05TracePrefixes.roleOrder .piopOpening
            decide) (V8SmzaOracleParser.digestAt messages.piop.bytes 0) =
            some execution.matrix := by
        rw [piopDigest]
        change currentFixedVectorDecodedAt ctx blockCap fixed c.statement .piopMatrix
          execution.hashFpp 0 = some execution.matrix
        rw [fixedPiopMatrix]
        change currentOracleAllAdvice (relationModel dsl certificates)
          (finiteGroupedDatabaseOracle
            (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
            database fallback)
          .piopOpening c.statement .piopMatrix (by decide) execution.hashFpp = _
        exact oracleOpeningMatrix
      change adviceFamily .piopOpening .piopMatrix _ _ = _
      rw [sameAdvice]
      exact fixedPiopMatrixCell
    · have notActive : .decsSample ≠ ctx.role := by rw [ctxRole]; decide
      have sameAdvice : adviceFamily .decsSample =
          currentOracleAllAdvice model oracle .decsSample c.statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
          .decsSample notActive]
        rfl
      change adviceFamily .decsSample .decsMatrix _ _ = _
      rw [sameAdvice]
      exact oracleEarlier.sampleCoefficients
    · have notActive : .decsSample ≠ ctx.role := by rw [ctxRole]; decide
      have sameAdvice : adviceFamily .decsSample =
          currentOracleAllAdvice model oracle .decsSample c.statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
          .decsSample notActive]
        rfl
      change adviceFamily .decsSample .piopOpening _ _ = _
      rw [sameAdvice]
      exact oracleEarlier.sampleOpening


end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFixedEarlierPiopCellsAmbientPiop

/-! # Same-stage accepted PIOP event coverage

This adapter takes one accepted grouped execution and genuine causal
`EarlierReadback` data. The PIOP vectors and grouped cells are reconstructed
from that branch's answer log; raw and filtered trace readbacks are derived
from the same execution and database.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopStageEventCoverageAmbientPiop

open scoped Classical
open HegemonCrypto.CanonicalBytes (Byte encodeLE)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchKeys branchAnswers branchClaims branchResult)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included answer_log_group_keys_represented)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05CurrentGroupedVerifierReplay (accepted_grouped_claims_supply_verifier_replay)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05ExecutablePcsClosure (ExecutionStages transcriptProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05RelationRefinement (RelationDsl GeneratedCertificates relationModel)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05GroupedSuffix (GroupCounter groupZero groupRepresentative)
open SmzaChallengeStageTargets (StageQuery parseStageQuery)
open SmzaRp05CurrentAcceptedPiopFailureEvents
  (current_piop_event_of_readbacks accepted_opening_call_role_readback)
open SmzaRp05CurrentAcceptedPiopRecordedOutputsAmbientPiop
  (accepted_matrix_call_and_vector accepted_opening_call_and_vector)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05CurrentAcceptedPiopOutputBindingAmbientPiop (actual_grouped_piop_matrix_route_output)
open SmzaRp05CurrentPiopRoleEvents
  (PiopRole currentPiopRoleEvent406 current_causal_matrix_failure_is_label_bad
   current_causal_opening_failure_is_label_bad)
open SmzaRp05CurrentAcceptedFilteredRoleTraces
  (current_stages_supply_filtered_role_traces currentOuterTarget)
open SmzaRp05CurrentAcceptedNonleafRoleReadback (accepted_stages_raw_nonleaf_outer_preambles)
open SmzaRp05CurrentAcceptedCausalPayloads (Records)
open SmzaRp05CurrentAcceptedEarlierAdvice
  (accepted_execution_supplies_earlier_advice_of_nonchallenge_retention)
open SmzaRp05AcceptedRoleLabels
  (EarlierReadback CausalPayloads causalTrace)
open SmzaRp05CurrentExecutedEarlierAdvice (currentOracleAllAdvice)
open SmzaRp05TracePrefixes (RelationModel TypedRoutes AllEarlierTables)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes)
open SmzaRp05CurrentRoleLabels (currentOuter targetOfRaw)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords global_extract_filtered_erase_challenge)
open SmzaRp04StatementRecordFilter (oneStatementFilter nonleafFilter)
open SmzaRecordedTracePath (RecordsCollisionFree)
open SmzaRp05CurrentCausalNonchallengeRetention (accepted_execution_causal_record_memberships)
open SmzaRp05ExecutablePcsClosureSampling (execution_stages_clean_matrix)
open SmzaRp05ExecutableChallengeStage (counterInput)
open SmzaRp05CurrentGroupedContext (parsed_representative_determines_grouped_counter_calls)
open SmzaRp05CertifiedReplaySchedule (ordinary_counter_roundtrip)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix groupKeyOf groupEncode groupAddress group_address_encode)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentMerkleGeometry (extract)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open SmzaRp05TracePrefixes (Payload Trace)
open SmzaRp05AcceptedRoleLabels (CausalPayloads)
open HegemonCrypto.SmallWoodTranscript (piopCoefficientDomain)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1600000

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local instance : DecidableEq RawInput := SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq
local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

private def acceptedFilteredRecords
    {Result : Type} (program : Program Result)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (ns : SmzaRp05LeafNamespace.Namespace) (statement : Statement) :=
  oneStatementFilter (globalLeafStatement ns) statement.toBytes
    (eraseChallengeRecords
      (rawRecords (fun key => groupRepresentative (included program key))
        (vectorOutputBytes groupZero) database))

/-- One successful grouped execution supplies current matrix/opening PIOP
role events from its own counter queries. The only failure inputs are the
genuine current source recovery and matrix/opening bad alternatives; no
call, vector, parser result, stored cell, or trace readback is assumed. -/
theorem accepted_execution_piop_failure_yields_role_event
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext)
    (ns : SmzaRp05LeafNamespace.Namespace) (dsl : RelationDsl)
    (c : SmzaRp05ContextAmbientDecoder.ParsedContext)
    (branch : Branches groupedDecode
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
    (accepted : branchResult groupedDecode
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
      branch = some ())
    (database : Database
      (Key (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (branchClaims
        (branchKeys (encode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          groupedDecode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch)
        (branchAnswers (encode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          groupedDecode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch))
      database)
    (fallback : RawDigest) [Fintype RawDigest]
    (certificates : GeneratedCertificates dsl)
    (bounded : ModelWithinProtocol (relationModel dsl certificates))
    (outerFuel : Nat) (outerEnough : 28 ≤ outerFuel)
    (authorized : Finset (List Byte)) (fresh : c.statement.toBytes ∉ authorized)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) transcript)
    (pcs : PcsStages ns execution.openingPending c.wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      c.wire.salt c.statement.toBytes (statementBindingWords c.statement) c.wire.tapes c.wire.paths
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) execution.hashFpp execution.pcsPending)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) = some c)
    (verifierAccepted : (verifierProgram ns dsl c.statement c.pending c.nonce c.wire).eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) = some ())
    (transcriptSuccess : (transcriptProgram ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire).eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) = some transcript)
    (collisionFree : RecordsCollisionFree
      (acceptedFilteredRecords
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database ns c.statement))
    (advice : (role : SmzaChallengeStageTargets.Role) →
      SmzaRp05TracePrefixes.AllEarlierTables (relationModel dsl certificates) role)
    (messages : CausalPayloads ns
      (extract (globalOnlineNext ns)
        (acceptedFilteredRecords
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
          database ns c.statement)
        28 .decs pcs.openingDigest))
    (earlier : EarlierReadback (relationModel dsl certificates) c.statement
      (fun role => advice role c.statement) messages
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) execution.matrix execution.opening)
    (source : V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140)
    (recovered : SmzaRp05CurrentTracePrefixes406.currentSourceDecoder406
      (SmzaRp05AcceptedRoleLabels.causalOracle ns
        (extract (globalOnlineNext ns)
          (acceptedFilteredRecords
            (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
            database ns c.statement) 28 .decs pcs.openingDigest)) messages.fpp
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) = some source)
    (failure :
      ((¬ HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
          ((relationModel dsl certificates).recoveredCandidate c.statement source.data).system) ∧
        execution.matrix ∈ SmzaRp04ChronologicalAlgebra.piopMatrixBadEvent
          ((relationModel dsl certificates).recoveredCandidate c.statement source.data)) ∨
      execution.opening ∈ SmzaRp04ChronologicalAlgebra.piopOpeningBadEvent
        ((relationModel dsl certificates).recoveredCandidate c.statement source.data) execution.matrix
        (SmzaRp05TracePrefixes.piopResponse messages.piop)) :
    currentPiopRoleEvent406 (relationModel dsl certificates) ns
      (fun key => groupRepresentative
        (included (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) key))
      groupZero (currentGroupedRoutes (relationModel dsl certificates) bounded) .matrix
      (advice .piopMatrix)
      outerFuel 28 authorized database ∨
    currentPiopRoleEvent406 (relationModel dsl certificates) ns
      (fun key => groupRepresentative
        (included (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) key))
      groupZero (currentGroupedRoutes (relationModel dsl certificates) bounded) .opening
      (advice .piopOpening)
      outerFuel 28 authorized database := by
  classical
  let program := producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire
  let oracle := finiteGroupedDatabaseOracle program database fallback
  let fullRecords := rawRecords (fun key => groupRepresentative (included program key))
    (vectorOutputBytes groupZero) database
  let filteredRecords := acceptedFilteredRecords program database ns c.statement
  obtain ⟨replayContext, producerSuccess₂, _verifierAccepted₂, retained'⟩ :=
    SmzaRp05ContextPhysicalBind.accepted_bind_grouped_claims_replay producer
      (fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
      branch () accepted database claims fallback
  have sameContext : c = replayContext := Option.some.inj
    (producerSuccess.symm.trans producerSuccess₂)
  subst replayContext
  have retainedOuter := SmzaRp05CurrentAcceptedNonleafRoleReadbackAmbient.accepted_stages_raw_nonleaf_outer_preambles
    program ns dsl c.statement c.pending c.nonce database fallback c.wire transcript execution pcs
    verifierAccepted transcriptSuccess outerFuel outerEnough collisionFree retained'
  have filteredTraces := SmzaRp05CurrentAcceptedFilteredRoleTracesAmbient.current_stages_supply_filtered_role_traces
    program ns dsl c.statement c.pending c.nonce database fallback c.wire transcript execution pcs
    verifierAccepted transcriptSuccess 28 (by decide) collisionFree retained'
  let model := relationModel dsl certificates
  let actualTrace : Trace := extract (globalOnlineNext ns) filteredRecords 28 .decs pcs.openingDigest
  have rawMatrixTraceEq := global_extract_filtered_erase_challenge ns fullRecords
    (fun input => globalLeafStatement ns input = none ∨
      globalLeafStatement ns input = some c.statement.toBytes)
    28 .fpp execution.hashFpp
  have rawOpeningTraceEq := global_extract_filtered_erase_challenge ns fullRecords
    (fun input => globalLeafStatement ns input = none ∨
      globalLeafStatement ns input = some c.statement.toBytes)
    28 .piop c.wire.hPiop
  let keyBytes := fun key : Key program => groupRepresentative (included program key)
  have stageClean : transcript.pendingXofFailure = false := by
    obtain ⟨cleanTranscript, cleanSuccess, clean, _, _⟩ :=
      SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl
        c.statement c.pending c.statement.toBytes (statementBindingWords c.statement) c.nonce c.wire oracle
        verifierAccepted
    have transcriptEq : cleanTranscript = transcript :=
      Option.some.inj (cleanSuccess.symm.trans transcriptSuccess)
    simpa [transcriptEq] using clean
  -- The caller's readback is explicitly indexed by the actual filtered trace;
  -- the following role traces and calls are reconstructed from this run.
  have matrixOutputs := accepted_matrix_call_and_vector producer ns dsl c
    branch database claims fallback producerSuccess transcript transcriptSuccess
    execution pcs stageClean certificates bounded
  rcases failure with matrixFailure | openingFailure
  · obtain ⟨vector, recorded, sampled⟩ := matrixOutputs
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
          some c.statement.toBytes := by
      unfold currentOuter
      change SmzaRp05CurrentRoleLabels.preambleFromTrace ns .piopMatrix
        (extract (globalOnlineNext ns) (nonleafFilter (globalLeafStatement ns) fullRecords)
          outerFuel (targetOfRaw .piopMatrix (keyBytes (encode program callInput))).1
            (targetOfRaw .piopMatrix (keyBytes (encode program callInput))).2) = _
      rw [targetRead]
      simpa only [program, fullRecords, currentOuterTarget,
        SmzaRp05CurrentAcceptedFilteredRoleTraces.currentOuterTarget,
        SmzaChallengeStageTargets.roleStage, query] using
        retainedOuter .piopMatrix
    have innerReadback : extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns) c.statement.toBytes fullRecords)
        28 (targetOfRaw .piopMatrix (keyBytes (encode program callInput))).1
          (targetOfRaw .piopMatrix (keyBytes (encode program callInput))).2 =
        causalTrace actualTrace .piopMatrix := by
      rw [targetRead]
      exact rawMatrixTraceEq.symm.trans (filteredTraces.2 .piopMatrix)
    have labelBad := current_causal_matrix_failure_is_label_bad model ns c.statement
      actualTrace messages (fun role => advice role c.statement)
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) execution.matrix execution.opening
      earlier source recovered (currentGroupedRoutes model bounded c.statement) vector sampled
      matrixFailure.1 matrixFailure.2
    exact Or.inl (current_piop_event_of_readbacks model ns keyBytes groupZero
      (currentGroupedRoutes model bounded) .matrix
      (advice .piopMatrix) outerFuel 28 authorized c.statement fresh
      (encode program callInput) vector database query representativeParsed rfl stored
      outerReadback actualTrace innerReadback labelBad)
  · obtain ⟨counter, vector, counterBound, recorded, sampled⟩ :=
      accepted_opening_call_and_vector producer ns dsl c branch database
        claims fallback producerSuccess transcript transcriptSuccess execution pcs
        stageClean certificates bounded
    let callInput := SmzaRp05CurrentOpeningProgram.openingCounterInput
      c.wire.hPiop c.nonce.val counter
    obtain ⟨_rolePrefix, _keyIdentity, representativeParsed, stored⟩ :=
      accepted_opening_call_role_readback program branch database claims fallback
        c.wire.hPiop c.nonce.val (by omega) ⟨counter, by
          rw [SmzaRp05GroupedSuffix.group_block_cap_eq]
          omega⟩ vector recorded
    have targetRead := current_actual_grouped_role_call_readback program branch
      (callInput, vector) recorded database claims fallback .piopOpening
      ⟨.piopOpening, c.wire.hPiop, c.nonce.val, 0⟩ representativeParsed rfl rfl
    obtain ⟨_, _, _, _, targetRead, _, _, _⟩ := targetRead
    have outerReadback : currentOuter ns keyBytes .piopOpening outerFuel
        (nonleafFilter (globalLeafStatement ns) fullRecords) (encode program callInput) =
          some c.statement.toBytes := by
      unfold currentOuter
      change SmzaRp05CurrentRoleLabels.preambleFromTrace ns .piopOpening
        (extract (globalOnlineNext ns) (nonleafFilter (globalLeafStatement ns) fullRecords)
          outerFuel (targetOfRaw .piopOpening (keyBytes (encode program callInput))).1
            (targetOfRaw .piopOpening (keyBytes (encode program callInput))).2) = _
      rw [targetRead]
      simpa only [program, fullRecords, currentOuterTarget,
        SmzaRp05CurrentAcceptedFilteredRoleTraces.currentOuterTarget,
        SmzaChallengeStageTargets.roleStage] using
        retainedOuter .piopOpening
    have innerReadback : extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns) c.statement.toBytes fullRecords)
        28 (targetOfRaw .piopOpening (keyBytes (encode program callInput))).1
          (targetOfRaw .piopOpening (keyBytes (encode program callInput))).2 =
        causalTrace actualTrace .piopOpening := by
      rw [targetRead]
      exact rawOpeningTraceEq.symm.trans (filteredTraces.2 .piopOpening)
    have labelBad := current_causal_opening_failure_is_label_bad model ns c.statement
      actualTrace messages (fun role => advice role c.statement)
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) execution.matrix execution.opening
      earlier source recovered (currentGroupedRoutes model bounded c.statement) vector sampled openingFailure
    exact Or.inr (current_piop_event_of_readbacks model ns keyBytes groupZero
      (currentGroupedRoutes model bounded) .opening
      (advice .piopOpening) outerFuel 28 authorized c.statement fresh
      (encode program callInput) vector database ⟨.piopOpening, c.wire.hPiop, c.nonce.val, 0⟩
      representativeParsed rfl stored outerReadback actualTrace innerReadback labelBad)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopStageEventCoverageAmbientPiop

/-! # Transfer selected X-view role evidence to its mixed completion

The accepted-classifier evidence is evaluated under a claims-completing
database.  This module transports its exact execution and PCS records to the
literal fixed/active completion from the selected mixed support.  Both tables
satisfy the same branch claims, so their program reads and verifier transcript
are stable; equality of the nonchallenge views preserves the filtered source
records used by the current decoder.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopExtractionFailureEventAmbientPiop

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
open SmzaRp05CurrentAcceptedPiopRecordedOutputsAmbientPiop
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
open SmzaRp05CurrentAcceptedFixedEarlierPiopCellsAmbientPiop (same_stage_fixed_piop_earlier_readback)
open SmzaRp05CurrentAcceptedPiopCausalCoverage (same_stage_piop_failure_has_causal_readback)
open SmzaRp05CurrentAcceptedPiopStageEventCoverageAmbientPiop (accepted_execution_piop_failure_yields_role_event)
open SmzaRp05CurrentAcceptedPiopFailureEvents
  (current_piop_event_of_readbacks accepted_opening_call_role_readback)
open SmzaRp05CurrentAcceptedPiopRecordedOutputsAmbientPiop
  (accepted_matrix_call_and_vector accepted_opening_call_and_vector)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05CurrentAcceptedPiopOutputBindingAmbientPiop (actual_grouped_piop_matrix_route_output)
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
set_option linter.unusedVariables false

local instance : DecidableEq RawInput :=
  SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq

local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

private def acceptedFilteredRecords
    {Result : Type} (program : Program Result)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (ns : SmzaRp05LeafNamespace.Namespace) (statement : SmzaRp05StatementNamespace.Statement) :=
  oneStatementFilter (SmzaRp05FilteredReadback.globalLeafStatement ns) statement.toBytes
    (eraseChallengeRecords
      (rawRecords (fun key => groupRepresentative (included program key))
        (vectorOutputBytes groupZero) database))

private theorem accepted_execution_selected_piop_failure_yields_role_event
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext)
    (ns : SmzaRp05LeafNamespace.Namespace) (dsl : RelationDsl)
    (c : SmzaRp05ContextAmbientDecoder.ParsedContext)
    (branch : Branches groupedDecode
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
    (accepted : branchResult groupedDecode
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
      branch = some ())
    (database : Database
      (Key (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (branchClaims
        (branchKeys (encode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          groupedDecode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch)
        (branchAnswers (encode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          groupedDecode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch))
      database)
    (fallback : RawDigest) [Fintype RawDigest]
    (certificates : GeneratedCertificates dsl)
    (bounded : ModelWithinProtocol (relationModel dsl certificates))
    (outerFuel : Nat) (outerEnough : 28 ≤ outerFuel)
    (authorized : Finset (List Byte)) (fresh : c.statement.toBytes ∉ authorized)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) transcript)
    (pcs : PcsStages ns execution.openingPending c.wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      c.wire.salt c.statement.toBytes (statementBindingWords c.statement) c.wire.tapes c.wire.paths
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) execution.hashFpp execution.pcsPending)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) = some c)
    (verifierAccepted : (verifierProgram ns dsl c.statement c.pending c.nonce c.wire).eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) = some ())
    (transcriptSuccess : (transcriptProgram ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire).eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) = some transcript)
    (collisionFree : RecordsCollisionFree
      (acceptedFilteredRecords
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database ns c.statement))
    (advice : (role : SmzaChallengeStageTargets.Role) →
      SmzaRp05TracePrefixes.AllEarlierTables (relationModel dsl certificates) role)
    (messages : CausalPayloads ns
      (extract (globalOnlineNext ns)
        (acceptedFilteredRecords
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
          database ns c.statement)
        28 .decs pcs.openingDigest))
    (earlier : EarlierReadback (relationModel dsl certificates) c.statement
      (fun role => advice role c.statement) messages
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) execution.matrix execution.opening)
    (source : V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140)
    (recovered : SmzaRp05CurrentTracePrefixes406.currentSourceDecoder406
      (SmzaRp05AcceptedRoleLabels.causalOracle ns
        (extract (globalOnlineNext ns)
          (acceptedFilteredRecords
            (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
            database ns c.statement) 28 .decs pcs.openingDigest)) messages.fpp
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) = some source)
    (which : PiopRole)
    (failure : match which with
      | .matrix =>
          (¬ HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
              ((relationModel dsl certificates).recoveredCandidate c.statement source.data).system ∧
            execution.matrix ∈ SmzaRp04ChronologicalAlgebra.piopMatrixBadEvent
              ((relationModel dsl certificates).recoveredCandidate c.statement source.data))
      | .opening =>
          execution.opening ∈ SmzaRp04ChronologicalAlgebra.piopOpeningBadEvent
            ((relationModel dsl certificates).recoveredCandidate c.statement source.data) execution.matrix
            (SmzaRp05TracePrefixes.piopResponse messages.piop)) :
    currentPiopRoleEvent406 (relationModel dsl certificates) ns
      (fun key => groupRepresentative
        (included (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) key))
      groupZero (currentGroupedRoutes (relationModel dsl certificates) bounded) which
      (advice which.toRole)
      outerFuel 28 authorized database := by
  classical
  let program := producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire
  let oracle := finiteGroupedDatabaseOracle program database fallback
  let fullRecords := rawRecords (fun key => groupRepresentative (included program key))
    (vectorOutputBytes groupZero) database
  let filteredRecords := acceptedFilteredRecords program database ns c.statement
  obtain ⟨replayContext, producerSuccess₂, _verifierAccepted₂, retained'⟩ :=
    SmzaRp05ContextPhysicalBind.accepted_bind_grouped_claims_replay producer
      (fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
      branch () accepted database claims fallback
  have sameContext : c = replayContext := Option.some.inj
    (producerSuccess.symm.trans producerSuccess₂)
  subst replayContext
  have retainedOuter := SmzaRp05CurrentAcceptedNonleafRoleReadbackAmbient.accepted_stages_raw_nonleaf_outer_preambles
    program ns dsl c.statement c.pending c.nonce database fallback c.wire transcript execution pcs
    verifierAccepted transcriptSuccess outerFuel outerEnough collisionFree retained'
  have filteredTraces := SmzaRp05CurrentAcceptedFilteredRoleTracesAmbient.current_stages_supply_filtered_role_traces
    program ns dsl c.statement c.pending c.nonce database fallback c.wire transcript execution pcs
    verifierAccepted transcriptSuccess 28 (by decide) collisionFree retained'
  let model := relationModel dsl certificates
  let actualTrace : Trace := extract (globalOnlineNext ns) filteredRecords 28 .decs pcs.openingDigest
  have rawMatrixTraceEq := global_extract_filtered_erase_challenge ns fullRecords
    (fun input => globalLeafStatement ns input = none ∨
      globalLeafStatement ns input = some c.statement.toBytes)
    28 .fpp execution.hashFpp
  have rawOpeningTraceEq := global_extract_filtered_erase_challenge ns fullRecords
    (fun input => globalLeafStatement ns input = none ∨
      globalLeafStatement ns input = some c.statement.toBytes)
    28 .piop c.wire.hPiop
  let keyBytes := fun key : Key program => groupRepresentative (included program key)
  have stageClean : transcript.pendingXofFailure = false := by
    obtain ⟨cleanTranscript, cleanSuccess, clean, _, _⟩ :=
      SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl
        c.statement c.pending c.statement.toBytes (statementBindingWords c.statement) c.nonce c.wire oracle
        verifierAccepted
    have transcriptEq : cleanTranscript = transcript :=
      Option.some.inj (cleanSuccess.symm.trans transcriptSuccess)
    simpa [transcriptEq] using clean
  -- The caller's readback is explicitly indexed by the actual filtered trace;
  -- the following role traces and calls are reconstructed from this run.
  have matrixOutputs := accepted_matrix_call_and_vector producer ns dsl c
    branch database claims fallback producerSuccess transcript transcriptSuccess
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
            some c.statement.toBytes := by
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
          (oneStatementFilter (globalLeafStatement ns) c.statement.toBytes fullRecords)
          28 (targetOfRaw .piopMatrix (keyBytes (encode program callInput))).1
            (targetOfRaw .piopMatrix (keyBytes (encode program callInput))).2 =
          causalTrace actualTrace .piopMatrix := by
        rw [targetRead]
        exact rawMatrixTraceEq.symm.trans (filteredTraces.2 .piopMatrix)
      have labelBad := current_causal_matrix_failure_is_label_bad model ns c.statement
        actualTrace messages (fun role => advice role c.statement)
        (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
          (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) execution.matrix execution.opening
        earlier source recovered (currentGroupedRoutes model bounded c.statement) vector sampled
        matrixFailure.1 matrixFailure.2
      exact (current_piop_event_of_readbacks model ns keyBytes groupZero
        (currentGroupedRoutes model bounded) .matrix
        (advice .piopMatrix) outerFuel 28 authorized c.statement fresh
        (encode program callInput) vector database query representativeParsed rfl stored
        outerReadback actualTrace innerReadback labelBad)
  | opening =>
      let openingFailure := failure
      obtain ⟨counter, vector, counterBound, recorded, sampled⟩ :=
        accepted_opening_call_and_vector producer ns dsl c branch database
          claims fallback producerSuccess transcript transcriptSuccess execution pcs
          stageClean certificates bounded
      let callInput := SmzaRp05CurrentOpeningProgram.openingCounterInput
        c.wire.hPiop c.nonce.val counter
      obtain ⟨_rolePrefix, _keyIdentity, representativeParsed, stored⟩ :=
        accepted_opening_call_role_readback program branch database claims fallback
          c.wire.hPiop c.nonce.val (by omega) ⟨counter, by
            rw [SmzaRp05GroupedSuffix.group_block_cap_eq]
            omega⟩ vector recorded
      have targetRead := current_actual_grouped_role_call_readback program branch
        (callInput, vector) recorded database claims fallback .piopOpening
        ⟨.piopOpening, c.wire.hPiop, c.nonce.val, 0⟩ representativeParsed rfl rfl
      obtain ⟨_, _, _, _, targetRead, _, _, _⟩ := targetRead
      have outerReadback : currentOuter ns keyBytes .piopOpening outerFuel
          (nonleafFilter (globalLeafStatement ns) fullRecords) (encode program callInput) =
            some c.statement.toBytes := by
        unfold currentOuter
        change SmzaRp05CurrentRoleLabels.preambleFromTrace ns .piopOpening
          (extract (globalOnlineNext ns) (nonleafFilter (globalLeafStatement ns) fullRecords)
            outerFuel (targetOfRaw .piopOpening (keyBytes (encode program callInput))).1
              (targetOfRaw .piopOpening (keyBytes (encode program callInput))).2) = _
        rw [targetRead]
        change SmzaRp05CurrentRoleLabels.preambleFromTrace ns .piopOpening
          (extract (globalOnlineNext ns) (nonleafFilter (globalLeafStatement ns) fullRecords)
            outerFuel .piop c.wire.hPiop) = _
        exact retainedOuter .piopOpening
      have innerReadback : extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) c.statement.toBytes fullRecords)
          28 (targetOfRaw .piopOpening (keyBytes (encode program callInput))).1
            (targetOfRaw .piopOpening (keyBytes (encode program callInput))).2 =
          causalTrace actualTrace .piopOpening := by
        rw [targetRead]
        exact rawOpeningTraceEq.symm.trans (filteredTraces.2 .piopOpening)
      have labelBad := current_causal_opening_failure_is_label_bad model ns c.statement
        actualTrace messages (fun role => advice role c.statement)
        (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
          (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) execution.matrix execution.opening
        earlier source recovered (currentGroupedRoutes model bounded c.statement) vector sampled openingFailure
      exact (current_piop_event_of_readbacks model ns keyBytes groupZero
        (currentGroupedRoutes model bounded) .opening
        (advice .piopOpening) outerFuel 28 authorized c.statement fresh
        (encode program callInput) vector database ⟨.piopOpening, c.wire.hPiop, c.nonce.val, 0⟩
        representativeParsed rfl stored outerReadback actualTrace innerReadback labelBad)

private def emptyInitialAdvice (model : RelationModel) (role : Role) :
    AllEarlierTables model role := fun _ _ _ _ => none

private def groupedRoleContext
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext)
    (ns : SmzaRp05LeafNamespace.Namespace)
 (model : RelationModel)
    (bounded : ModelWithinProtocol model) (role : Role) :
    Context (Key := Key (SmzaRp05ContextAmbientDecoder.fixedNamespaceContextProgram ns producer))
      (Counter := GroupCounter) (BaseWork := BaseWork) :=
  currentGroupedContext (SmzaRp05ContextAmbientDecoder.fixedNamespaceContextProgram ns producer)
    model bounded ns role (emptyInitialAdvice model role) 28 28 (fun _ => ∅)

private def groupedFailureSelector
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext)
    (ns : SmzaRp05LeafNamespace.Namespace)
 (fallback : RawDigest)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (role : Role)
    (branch : Branches groupedDecode
      (SmzaRp05ContextAmbientDecoder.fixedNamespaceContextProgram ns producer)) :
    (view : XKey (nonchallengeRawKeySet
      (groupedRoleContext (BaseWork := BaseWork) producer ns model bounded role)) →
        Option (VectorOutput GroupCounter)) →
      SmzaRp05CurrentAdaptiveExecution.Work (Counter := GroupCounter)
        (BaseWork := BaseWork) → Prop :=
  let ctx := groupedRoleContext (BaseWork := BaseWork) producer ns model bounded role
  fun view _work => SmzaRp05ContextAmbientCoverage.ambientXViewFailureRoleSelector
    producer ns fallback 28 ctx role branch view

attribute [local irreducible]
  HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates.currentDsl
  HegemonCrypto.SmallWood.SmzaRp05RelationRefinement.candidate
  HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
  HegemonCrypto.SmallWood.SmzaRp04ChronologicalAlgebra.piopMatrixBadEvent
  HegemonCrypto.SmallWood.SmzaRp04ChronologicalAlgebra.piopOpeningBadEvent

theorem grouped_piop_failure_support_implies_current_advice_event_or_missing_claims
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext)
    (ns : SmzaRp05LeafNamespace.Namespace)
 (fallback : RawDigest)
    (certificates : GeneratedCertificates currentDsl)
    (bounded : ModelWithinProtocol (relationModel currentDsl certificates))
    (blockCap : Role → Nat) (role : PiopRole)
    (positiveDecsMatrixCap : 0 < blockCap .decsMatrix)
    (positivePiopMatrixCap : 0 < blockCap .piopMatrix)
    (branch : Branches groupedDecode
      (SmzaRp05ContextAmbientDecoder.fixedNamespaceContextProgram ns producer))
    (fixed : FixedTable
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        (relationModel currentDsl certificates) bounded role.toRole) blockCap)
    (dummy : ActiveKey role.toRole blockCap
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        (relationModel currentDsl certificates) bounded role.toRole).keyBytes)
    (state : CmsState
      (Key := Key (SmzaRp05ContextAmbientDecoder.fixedNamespaceContextProgram ns producer))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (basis : Basis (ActiveKey role.toRole blockCap
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        (relationModel currentDsl certificates) bounded role.toRole).keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (SmzaRp05ConditionedExecution.ActiveMemory
        (groupedRoleContext (BaseWork := BaseWork) producer ns
          (relationModel currentDsl certificates) bounded role.toRole)))
    (cap : Nat)
    (support : selectedRoleState
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        (relationModel currentDsl certificates) bounded role.toRole)
      blockCap (encode (SmzaRp05ContextAmbientDecoder.fixedNamespaceContextProgram ns producer))
      groupedDecode (SmzaRp05ContextAmbientDecoder.fixedNamespaceContextProgram ns producer)
      branch fixed
      (fixedFiberToActive
        (groupedRoleContext (BaseWork := BaseWork) producer ns
          (relationModel currentDsl certificates) bounded role.toRole)
        blockCap dummy fixed (otherRoleTransform
          (groupedRoleContext (BaseWork := BaseWork) producer ns
            (relationModel currentDsl certificates) bounded role.toRole)
          blockCap state))
      (groupedFailureSelector (BaseWork := BaseWork) producer ns fallback
        (relationModel currentDsl certificates) bounded role.toRole branch) basis ≠ 0) :
    event (currentAdviceEventSpec
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        (relationModel currentDsl certificates) bounded role.toRole)
      blockCap fixed cap)
      (SmzaRp05ConditionedExecution.activeMemoryEquiv
        (groupedRoleContext (BaseWork := BaseWork) producer ns
          (relationModel currentDsl certificates) bounded role.toRole) basis.workspace)
      basis.database ∨
    ¬ ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims
        (groupedRoleContext (BaseWork := BaseWork) producer ns
          (relationModel currentDsl certificates) bounded role.toRole)
        blockCap (encode (SmzaRp05ContextAmbientDecoder.fixedNamespaceContextProgram ns producer))
        groupedDecode (SmzaRp05ContextAmbientDecoder.fixedNamespaceContextProgram ns producer) branch)
      basis.database := by
  classical
  let model := relationModel currentDsl certificates
  let program := SmzaRp05ContextAmbientDecoder.fixedNamespaceContextProgram ns producer
  let ctx := groupedRoleContext (BaseWork := BaseWork) producer ns model bounded role.toRole
  let select := groupedFailureSelector (BaseWork := BaseWork) producer ns fallback
    model bounded role.toRole branch
  let fiberInitial := fixedFiberToActive ctx blockCap dummy fixed
    (otherRoleTransform ctx blockCap state)
  by_cases challengeClaims : ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims ctx blockCap (encode program) groupedDecode program branch)
      basis.database
  · have evidence := SmzaRp05ContextAmbientSupport.selected_ambient_failure_role_replays_on_completion
      producer ns fallback 28
      ctx blockCap (by intro key; rfl) branch fixed
      fiberInitial basis challengeClaims support
    rcases evidence with ⟨c, recordsCollisionFree, completionOracle, oracleEq, transcript, producerSuccess,
      verifierAccepted, transcriptSuccess, execution, pcs, coordinates, query, input,
      ordered, image, indexes, inputMember, hashMember, currentOutcome, labelOutcome,
      roleFailure⟩
    subst completionOracle
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
      change producer.eval oracle = some c at producerSuccess
      change (verifierProgram ns currentDsl c.statement c.pending c.nonce c.wire).eval oracle = some ()
        at verifierAccepted
      change (SmzaRp05ContextAmbientDecoder.fixedNamespaceContextProgram ns producer).eval oracle = some ()
      rw [SmzaRp05ContextAmbientDecoder.fixedNamespaceContextProgram, Program.eval_bind, producerSuccess]
      exact verifierAccepted
    have accepted : branchResult groupedDecode program branch = some () := by
      have recordResult : (program.record oracle).1 = branchResult groupedDecode program branch :=
        congrArg Prod.fst actualRecord.1
      calc
        branchResult groupedDecode program branch = (program.record oracle).1 := recordResult.symm
        _ = program.eval oracle := Program.record_result oracle program
        _ = some () := actualSuccess
    have nonchallengeRetained : ∀ call,
        call ∈ ((verifierProgram ns currentDsl c.statement c.pending c.nonce c.wire).record oracle).2 →
        parseStageQuery call.1 = none →
          call ∈ rawRecords (fun key => groupRepresentative (included program key))
            (vectorOutputBytes groupZero) completed := by
      intro call member queryNone
      have inProgram := Program.bind_log_right oracle producer
        (fun output => verifierProgram ns currentDsl output.statement output.pending output.nonce output.wire)
        c producerSuccess member
      have inProgramRecord : call ∈ (program.record oracle).2 := by
        simpa [program, SmzaRp05ContextAmbientDecoder.fixedNamespaceContextProgram] using inProgram
      have recordLog := congrArg Prod.snd actualRecord.1
      change (program.record oracle).2 =
        SmzaRp05PhysicalAcceptedReplayLite.rawLog groupedDecode program branch at recordLog
      have inRawLog : call ∈ SmzaRp05PhysicalAcceptedReplayLite.rawLog
          groupedDecode program branch := by
        rw [recordLog] at inProgramRecord
        exact inProgramRecord
      exact actualRecord.2 call inRawLog queryNone
    have causal := same_stage_piop_failure_has_causal_readback role ns c.statement c.pending c.nonce
      c.wire oracle transcript execution pcs
      (rawRecords (fun key => groupRepresentative (included program key))
        (vectorOutputBytes groupZero) completed)
      verifierAccepted transcriptSuccess nonchallengeRetained recordsCollisionFree
      input query hashMember roleFailure
    rcases causal with ⟨messages, openingRecorded, finalRecorded, hashRetained,
      _rootTraceEq, _piopTraceEq, roleFailureOnTrace⟩
    let causalTrace := V8Smz9CoherentMerkleGeometry.extract
      (SmzaRp05FilteredDecoderInstability.globalOnlineNext ns)
      (SmzaRp04StatementRecordFilter.oneStatementFilter
        (SmzaRp05FilteredReadback.globalLeafStatement ns) c.statement.toBytes
        (eraseChallengeRecords
          (rawRecords (fun key => groupRepresentative (included program key))
            (vectorOutputBytes groupZero) completed))) 28 .decs pcs.openingDigest
    obtain ⟨payloadTrace, payloadTraceEq, payloadMessages, fppDigest,
      piopDigest, decsDigest⟩ := current_causal_payloads_and_targets_of_stages
      ns currentDsl c.statement c.pending c.nonce c.wire oracle transcript execution pcs
      (oneStatementFilter
        (SmzaRp05FilteredReadback.globalLeafStatement ns) c.statement.toBytes
        (eraseChallengeRecords
          (rawRecords (fun key => groupRepresentative (included program key))
            (vectorOutputBytes groupZero) completed))) recordsCollisionFree
      openingRecorded finalRecorded hashRetained
    cases payloadTraceEq
    obtain ⟨cleanTranscript, cleanTranscriptSuccess, transcriptClean, _, _⟩ :=
      SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns currentDsl
        c.statement c.pending c.statement.toBytes (statementBindingWords c.statement) c.nonce c.wire oracle
        verifierAccepted
    have sameTranscript : cleanTranscript = transcript :=
      Option.some.inj (cleanTranscriptSuccess.symm.trans transcriptSuccess)
    have suppliedTranscriptClean : transcript.pendingXofFailure = false := by
      rw [← sameTranscript]
      exact transcriptClean
    have stagesClean :=
      SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix ns currentDsl c.statement
        c.pending c.statement.toBytes (statementBindingWords c.statement) c.nonce c.wire oracle transcript
        execution suppliedTranscriptClean
    have coefficientsClean : pcs.post.pending = false := pcs.pendingReturned.symm.trans stagesClean.1
    have openingCleanData := SmzaRp05ExecutablePcsClosureClean.pcs_stages_clean ns
      execution.openingPending c.wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      c.wire.salt c.statement.toBytes (statementBindingWords c.statement) c.wire.tapes c.wire.paths
      oracle execution.hashFpp execution.pcsPending pcs stagesClean.1
    have openingClean : execution.openingPending = false := openingCleanData.1
    have actualEarlier := SmzaRp05CurrentExecutedEarlierAdvice.actual_execution_supplies_earlier_readback
      currentDsl certificates c.statement ns c.pending c.nonce c.wire oracle transcript execution pcs
      (oneStatementFilter (SmzaRp05FilteredReadback.globalLeafStatement ns) c.statement.toBytes
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
        SmzaRp05AcceptedRoleLabels.EarlierReadback model c.statement
          (fun selected => SmzaRp05CurrentExecutedEarlierAdvice.currentOracleAllAdvice
            model oracle selected c.statement)
          messages
          (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
            (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) execution.matrix execution.opening := by
      change SmzaRp05AcceptedRoleLabels.EarlierReadback (relationModel currentDsl certificates)
        c.statement (fun selected => currentOracleAllAdvice
          (relationModel currentDsl certificates) oracle selected c.statement)
        sourceMessages
        (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
          (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) execution.matrix execution.opening
        at oracleEarlier
      change SmzaRp05AcceptedRoleLabels.EarlierReadback (relationModel currentDsl certificates)
        c.statement (fun selected => currentOracleAllAdvice
          (relationModel currentDsl certificates) oracle selected c.statement)
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
      producer ns currentDsl c branch accepted completed claims
      fallback certificates bounded role.toRole (by cases role <;> simp [PiopRole.toRole])
      (currentFixedAdvice ctx blockCap fixed) 28 28 (fun _ => ∅) blockCap dummy fixed
      state basis physicalNonzero positiveDecsMatrixCap positivePiopMatrixCap
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
                ((relationModel currentDsl certificates).recoveredCandidate c.statement source.data).system ∧
              execution.matrix ∈ SmzaRp04ChronologicalAlgebra.piopMatrixBadEvent
                ((relationModel currentDsl certificates).recoveredCandidate c.statement source.data)) :=
          ⟨notFull, matrixBad⟩
        have selectedStageRoleEvent := accepted_execution_selected_piop_failure_yields_role_event
          producer ns currentDsl c branch accepted completed claims fallback
          certificates bounded 28 (by decide) ∅ (by simp) transcript execution pcs
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
              ((relationModel currentDsl certificates).recoveredCandidate c.statement source.data)
              execution.matrix (SmzaRp05TracePrefixes.piopResponse messages.piop) :=
          openingBad
        have selectedStageRoleEvent := accepted_execution_selected_piop_failure_yields_role_event
          producer ns currentDsl c branch accepted completed claims fallback
          certificates bounded 28 (by decide) ∅ (by simp) transcript execution pcs
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
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopExtractionFailureEventAmbientPiop