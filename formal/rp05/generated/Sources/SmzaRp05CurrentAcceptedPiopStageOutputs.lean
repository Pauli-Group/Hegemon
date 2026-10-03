import SmzaRp05CurrentAcceptedPiopOutputBinding
import SmzaRp05CurrentExecutedPiopMatrixReadback
import SmzaRp05CurrentExecutedOpeningOutput
import SmzaRp05ExecutablePcsClosureClean
import SmzaRp05ExecutablePcsClosureSampling
import SmzaRp05PiopMatrixStage
import SmzaRp05PcsToFinalProgram
import SmzaRp05CurrentOpeningProgram
import SmzaRp05RelationRefinement

/-! # Accepted same-run PIOP stage endpoints

Compose grouped answer-log output binding with the executable decoder
readbacks for one and the same verifier execution. These are deterministic
stage equalities; no new probability or acceptance premise is introduced.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopStageOutputs

open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite (Branches answerLog)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode)
open SmzaRp05CurrentAcceptedPiopOutputBinding (actual_grouped_piop_matrix_route_output
  actual_grouped_piop_opening_route_output)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes)
open SmzaRp05CurrentExecutedPiopMatrixReadback
  (execution_piop_matrix_is_actual_role_output)
open SmzaRp05CurrentExecutedOpeningOutput (execution_stages_current_raw_opening)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05RelationRefinement (RelationDsl GeneratedCertificates relationModel)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05TracePrefixes (RelationModel)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05GroupedSuffix (GroupCounter)
open SmzaChallengeStageTargets (Role)
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
open HegemonCrypto.CanonicalBytes (Byte)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000

/-- An answer-log call at the actual same-run PIOP matrix seed decodes, on
the current grouped route, to exactly that execution's matrix. The stored
vector and all-coordinate route are derived by the output-binding theorem. -/
theorem actual_grouped_piop_matrix_is_stage_matrix
    {Result : Type} (program : Program Result)
    (branch : Branches groupedDecode program)
    (call : RawInput × VectorOutput GroupCounter)
    (recorded : call ∈ answerLog groupedDecode program branch)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys (encode program) groupedDecode program branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers (encode program) groupedDecode program branch))
      database)
    (fallback : RawDigest) (dsl : RelationDsl)
    (certificates : GeneratedCertificates dsl) (ns : Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire (finiteGroupedDatabaseOracle program database fallback) transcript)
    (clean : transcript.pendingXofFailure = false)
    (bounded : ModelWithinProtocol (relationModel dsl certificates))
    (inputEq : call.1 = counterInput piopCoefficientDomain execution.hashFpp 0) :
    actualPiopMatrixOutput
      (currentGroupedRoutes (relationModel dsl certificates) bounded statement).piopMatrix
      call.2 = some execution.matrix := by
  let model := relationModel dsl certificates
  have grouped := actual_grouped_piop_matrix_route_output program branch call recorded
    database claims fallback model bounded statement execution.hashFpp inputEq
  have executed := execution_piop_matrix_is_actual_role_output ns dsl statement pending
    statement.toBytes (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
    nonce wire (finiteGroupedDatabaseOracle program database fallback) transcript execution clean
  simpa [model, relationModel] using grouped.trans executed

/-- A same-run accepted opening-counter answer fixes the decoder on that
nonce's grouped route to the actual execution's opening object. The selected
nonce and selected call are supplied by the actual execution/log adapters;
this theorem does not conflate other nonce cells. -/
theorem actual_grouped_piop_opening_is_stage_opening
    {Result : Type} (program : Program Result)
    (branch : Branches groupedDecode program)
    (call : RawInput × VectorOutput GroupCounter)
    (recorded : call ∈ answerLog groupedDecode program branch)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys (encode program) groupedDecode program branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers (encode program) groupedDecode program branch))
      database)
    (fallback : RawDigest) (dsl : RelationDsl)
    (certificates : GeneratedCertificates dsl) (ns : Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire (finiteGroupedDatabaseOracle program database fallback) transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths (finiteGroupedDatabaseOracle program database fallback)
      execution.hashFpp execution.pcsPending)
    (clean : transcript.pendingXofFailure = false)
    (bounded : ModelWithinProtocol (relationModel dsl certificates))
    (counter : GroupCounter)
    (inputEq : call.1 = openingCounterInput wire.hPiop nonce.val counter.val) :
    actualPiopOpeningOutput
      (currentGroupedRoutes (relationModel dsl certificates) bounded statement).piopOpening
      call.2 = some execution.opening := by
  let model := relationModel dsl certificates
  have matrixClean := SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix
    ns dsl statement pending statement.toBytes
    (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
    nonce wire (finiteGroupedDatabaseOracle program database fallback) transcript execution clean
  have openingClean := SmzaRp05ExecutablePcsClosureClean.pcs_stages_clean
    ns execution.openingPending wire.hPiop
    (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
    execution.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
    wire.salt statement.toBytes
    (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
    wire.tapes wire.paths (finiteGroupedDatabaseOracle program database fallback)
    execution.hashFpp execution.pcsPending pcs matrixClean.1
  obtain ⟨_, _, _, _, _, executedOpening⟩ :=
    execution_stages_current_raw_opening ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire (finiteGroupedDatabaseOracle program database fallback) transcript execution
      openingClean.1
  have grouped := actual_grouped_piop_opening_route_output program branch call recorded
    database claims fallback model bounded statement wire.hPiop nonce.val
    nonce.isLt counter inputEq
  simpa [model, relationModel] using grouped.trans executedOpening

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopStageOutputs
