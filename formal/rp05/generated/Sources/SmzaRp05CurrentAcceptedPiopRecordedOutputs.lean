import SmzaRp05CurrentAcceptedPiopStageReadback
import SmzaRp05CurrentAcceptedPiopRecordLift
import SmzaRp05CurrentAcceptedPiopRoleCalls
import SmzaRp05CurrentOpeningSelectedRetention
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentAcceptedPiopStageOutputs
import SmzaRp05ExecutablePcsClosureClean
import SmzaRp05GroupedSuffix

/-! # Accepted PIOP calls with their recorded vectors

These same-run adapters expose both the accepted branch's actual answer-log
membership and the current decoder result on the same returned vector.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopRecordedOutputs

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
open SmzaRp05CurrentAcceptedPiopRecordLift
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
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
    (database : Database
      (Key (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys
          (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers
          (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) branch))
      database)
    (fallback : RawDigest) :
    let program := producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire
    let oracle := finiteGroupedDatabaseOracle program database fallback
    program.record oracle =
      (branchResult groupedDecode program branch,
       rawLog groupedDecode program branch) := by
  let program := producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire
  let oracle := finiteGroupedDatabaseOracle program database fallback
  exact (actual_program_grouped_claims_replay_and_retain program branch database claims fallback).1

/-- Return the actual answer-log pair for the successful matrix sampler's
counter-zero query, along with its exact same-run decoder result. -/
theorem accepted_matrix_call_and_vector
    (producer : Program ExistingProofFieldView) (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
    (database : Database
      (Key (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys
          (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers
          (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) branch))
      database)
    (fallback : RawDigest) (wire : ExistingProofFieldView)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun actualWire => verifierProgram ns dsl statement pending nonce actualWire)
        database fallback) = some wire)
    (transcript : ReconstructedTranscript)
    (transcriptSuccess : (transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire).eval
        (finiteGroupedDatabaseOracle
          (producer.bind fun actualWire => verifierProgram ns dsl statement pending nonce actualWire)
          database fallback) = some transcript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire
      (finiteGroupedDatabaseOracle
        (producer.bind fun actualWire => verifierProgram ns dsl statement pending nonce actualWire)
        database fallback) transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (sameProofRows execution.middle.pcs execution.piop) execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement) wire.tapes wire.paths
      (finiteGroupedDatabaseOracle
        (producer.bind fun actualWire => verifierProgram ns dsl statement pending nonce actualWire)
        database fallback) execution.hashFpp execution.pcsPending)
    (clean : transcript.pendingXofFailure = false)
    (certificates : GeneratedCertificates dsl)
    (bounded : ModelWithinProtocol (relationModel dsl certificates)) :
    ∃ output, (SmzaRp05ExecutableChallengeStage.counterInput
        HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain execution.hashFpp 0,
        output) ∈ answerLog groupedDecode
          (producer.bind fun actualWire => verifierProgram ns dsl statement pending nonce actualWire) branch ∧
      actualPiopMatrixOutput
        (SmzaRp05CurrentGroupedRoutes.currentGroupedRoutes
          (relationModel dsl certificates) bounded statement).piopMatrix output =
        some execution.matrix := by
  let program := producer.bind fun actualWire => verifierProgram ns dsl statement pending nonce actualWire
  let oracle := finiteGroupedDatabaseOracle program database fallback
  have recordEq := branch_record_equation producer ns dsl statement pending nonce branch database claims fallback
  have widthPositive : 0 < dsl.width statement := by
    simp [SmzaRp05RelationRefinement.RelationDsl.width,
      certificates.nonlinear.nonlinearCountExact]
  have finalClean : execution.finalPending = false := by
    have projected := congrArg ReconstructedTranscript.pendingXofFailure execution.reconstructed
    have eq : execution.finalPending = transcript.pendingXofFailure := by
      simpa [SmzaRp05ExecutableReconstruction.reconstruct] using projected
    exact eq.trans clean
  have rawCall := execution_matrix_counter_zero_raw_call ns dsl statement pending nonce wire
    oracle transcript execution pcs widthPositive finalClean
  let input := SmzaRp05ExecutableChallengeStage.counterInput
    HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain execution.hashFpp 0
  obtain ⟨output, recorded, _digestEq⟩ := transcript_record_pair_is_accepted_branch_answer
    producer ns dsl statement pending nonce wire oracle transcript transcriptSuccess branch
    recordEq producerSuccess input (oracle input) (by simpa [input] using rawCall)
  have decoded := actual_grouped_piop_matrix_is_stage_matrix program branch
    (input, output) recorded database claims fallback dsl certificates ns statement pending
    nonce wire transcript execution clean bounded rfl
  exact ⟨output, recorded, decoded⟩

/-- Return the selected opening attempt's actual branch answer-log vector.
The counter index and its bound are the values from the same executed scan. -/
theorem accepted_opening_call_and_vector
    (producer : Program ExistingProofFieldView) (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
    (database : Database
      (Key (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys
          (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers
          (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) branch))
      database)
    (fallback : RawDigest) (wire : ExistingProofFieldView)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun actualWire => verifierProgram ns dsl statement pending nonce actualWire)
        database fallback) = some wire)
    (transcript : ReconstructedTranscript)
    (transcriptSuccess : (transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire).eval
        (finiteGroupedDatabaseOracle
          (producer.bind fun actualWire => verifierProgram ns dsl statement pending nonce actualWire)
          database fallback) = some transcript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire
      (finiteGroupedDatabaseOracle
        (producer.bind fun actualWire => verifierProgram ns dsl statement pending nonce actualWire)
        database fallback) transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (sameProofRows execution.middle.pcs execution.piop) execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement) wire.tapes wire.paths
      (finiteGroupedDatabaseOracle
        (producer.bind fun actualWire => verifierProgram ns dsl statement pending nonce actualWire)
        database fallback) execution.hashFpp execution.pcsPending)
    (clean : transcript.pendingXofFailure = false)
    (certificates : GeneratedCertificates dsl)
    (bounded : ModelWithinProtocol (relationModel dsl certificates)) :
    ∃ counter output, counter < 5 ∧
      (SmzaRp05CurrentOpeningProgram.openingCounterInput wire.hPiop nonce.val counter,
        output) ∈ answerLog groupedDecode
          (producer.bind fun actualWire => verifierProgram ns dsl statement pending nonce actualWire) branch ∧
      actualPiopOpeningOutput
        (SmzaRp05CurrentGroupedRoutes.currentGroupedRoutes
          (relationModel dsl certificates) bounded statement).piopOpening output =
        some execution.opening := by
  let program := producer.bind fun actualWire => verifierProgram ns dsl statement pending nonce actualWire
  let oracle := finiteGroupedDatabaseOracle program database fallback
  have recordEq := branch_record_equation producer ns dsl statement pending nonce branch database claims fallback
  have matrixClean := execution_stages_clean_matrix ns dsl statement pending
    statement.toBytes (statementBindingWords statement) nonce wire oracle transcript execution clean
  have openingClean := pcs_stages_clean ns execution.openingPending wire.hPiop
    (sameProofRows execution.middle.pcs execution.piop) execution.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
    wire.salt statement.toBytes (statementBindingWords statement) wire.tapes wire.paths
    oracle execution.hashFpp execution.pcsPending pcs matrixClean.1
  obtain ⟨counter, counterBound, member⟩ :=
    successful_canonical_opening_retains_selected_nonce_call_in_verifier_record
      ns dsl statement pending nonce wire oracle transcript execution pcs openingClean.1
      transcriptSuccess
  have fitsGroup : counter < SmzaRp05GroupedSuffix.groupBlockCap := by
    rw [SmzaRp05GroupedSuffix.group_block_cap_eq]
    omega
  let groupCounter : GroupCounter := ⟨counter, fitsGroup⟩
  let input := SmzaRp05CurrentOpeningProgram.openingCounterInput wire.hPiop nonce.val counter
  obtain ⟨output, recorded, _digestEq⟩ := verifier_record_pair_is_accepted_branch_answer
    producer ns dsl statement pending nonce wire oracle branch recordEq producerSuccess
    input (oracle input)
    (by simpa only [input, SmzaRp05ExecutablePcsClosureStatement.verifierProgram] using member)
  have decoded := actual_grouped_piop_opening_is_stage_opening program branch
    (input, output) recorded database claims fallback dsl certificates ns statement pending
    nonce wire transcript execution pcs clean bounded groupCounter rfl
  exact ⟨counter, output, counterBound, recorded, decoded⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopRecordedOutputs
