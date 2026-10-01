import SmzaRp05AcceptedRoleLabels
import SmzaRp05CurrentExecutedDecsCoefficients
import SmzaRp05CurrentExecutedPiopMatrixReadback
import SmzaRp05CurrentCanonicalOpeningOutput
import SmzaRp05CurrentAcceptedCausalPayloads
import SmzaRp05CurrentDecsMatrixSampling

/-! Earlier-role advice built directly from the same current-profile source
oracle. Its outputs are current samplers, not the historical `rawRoleInput`
decoder. The final readback theorem consumes the three actual causal message
digests and derives all five earlier-role cells from executed-stage results. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedEarlierAdvice

open SmzaRp05AcceptedRoleLabels (CausalPayloads EarlierReadback)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables RoleOutput Trace)
open SmzaChallengeStageTargets (Role)
open SmzaRp05ConditionedExecution (firstSome canonicalOpeningNonceOrder)
open SmzaRp04RawRoleSampling
open SmzaRp04RawMcaSampling
open SmzaRp05CurrentExecutedMatrixReadback (currentDecsMatrixVector)
open SmzaRp05CurrentDecsMatrixSampling (currentActualDecsMatrixOutput)
open SmzaRp05CurrentExecutedPiopMatrixReadback (currentPiopMatrixVector)
open SmzaRp05CurrentExecutedOpeningOutput (currentOpeningVector)
open SmzaRp05ExecutableChallengeStage (counterInput)
open SmzaRp05CurrentOpeningProgram (openingCounterInput)
open HegemonCrypto.SmallWoodTranscript (decsFixedSamplingDomain)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutableMerkleVerifier (Oracle)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open SmzaRp05PcsWireProjection (DecodedMiddleWire)
open SmzaRp05StatementNamespace (Statement)
open V8Smz9AdaptiveFiniteAccounting.Historical (piopOpenings)
open SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients)
open SmzaRp05CurrentExecutedDecsCoefficients
open SmzaRp05CurrentExecutedPiopMatrixReadback
open SmzaRp05CurrentCanonicalOpeningOutput
open SmzaRp05CurrentAcceptedCausalPayloads
open SmzaRecordedTracePath (RecordsCollisionFree)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext)
open SmzaRp05ExecutableChallengeStage (FieldWord)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9RawCounterCompiler (digestCallCap)
open V8Smz9PiopSoundness (Matrix Opening)
open HegemonCrypto.CanonicalBytes (Byte)

set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 800000
noncomputable section

abbrev Records := SmzaRp05CurrentAcceptedCausalPayloads.Records

/-- Direct current-source decoder for every earlier challenge role. These
tables have only the role-local capped counter domain; they do not reinterpret
a historical framing or route a raw table through an unrelated grouped key. -/
def currentOracleDecodedAt (model : RelationModel)
    (oracle : Oracle) (statement : SmzaRp05StatementNamespace.Statement)
    (role : Role) (target : V8SmzaOracleParser.RawDigest) :
    Option (RoleOutput model statement role) :=
  match role with
  | .decsMatrix => currentActualDecsMatrixOutput
      (Equiv.refl (Fin (digestCallCap (140 * 5))))
      (currentDecsMatrixVector oracle target)
  | .piopMatrix => actualPiopMatrixOutput
      (Equiv.refl (Fin (digestCallCap (5 * model.width statement))))
      (currentPiopMatrixVector oracle target (model.width statement))
  | .piopOpening => firstSome
      (fun nonce : Fin 16 => actualPiopOpeningOutput
        (Equiv.refl (Fin (digestCallCap piopOpenings)))
        (currentOpeningVector oracle target nonce.val)) canonicalOpeningNonceOrder
  | .decsSample => actualDecsSampleOutput
      (Equiv.refl (Fin (digestCallCap q38CandidateCount))).toEmbedding
      (fun counter : Fin (digestCallCap q38CandidateCount) => rawDigestBits
        (oracle (counterInput decsFixedSamplingDomain target counter.val)))

def currentOracleAllAdvice (model : RelationModel) (oracle : Oracle)
    (selected : Role) : AllEarlierTables model selected :=
  fun statement earlier _ target =>
    currentOracleDecodedAt model oracle statement earlier target

/-- Actual current execution outputs provide the five strictly-earlier table
cells consumed by `EarlierReadback`, using causal payloads and digest prefixes
constructed from the same execution's retained records. -/
theorem actual_execution_supplies_earlier_readback
    (dsl : RelationDsl)
    (certificates : SmzaRp05RelationRefinement.GeneratedCertificates dsl)
    (statement : SmzaRp05StatementNamespace.Statement)
    (ns : Namespace) (pending : Bool) (nonce : Fin (2 ^ 32))
    (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending)
    [Fintype V8SmzaOracleParser.RawDigest]
    (records : Records) (collisionFree : RecordsCollisionFree records)
    (openingRecorded : (pcs.openingInput, pcs.openingDigest) ∈ records)
    (finalRecorded : (SmzaRp05ExecutableFinalVerifier.finalInput transcript,
      wire.hPiop) ∈ records)
    (hashRecordRetained : ∀ call,
      call ∈ (pcs.hashProgram.record oracle).2 → call ∈ records)
    (coefficientsClean : pcs.post.pending = false)
    (transcriptClean : transcript.pendingXofFailure = false)
    (openingClean : execution.openingPending = false) :
    ∃ trace : Trace,
      trace = V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) records
        28 .decs pcs.openingDigest ∧
      ∃ messages : CausalPayloads ns trace,
      EarlierReadback (SmzaRp05RelationRefinement.relationModel dsl certificates) statement
        (fun selected => currentOracleAllAdvice
          (SmzaRp05RelationRefinement.relationModel dsl certificates)
          oracle selected statement)
        messages (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
        execution.matrix execution.opening := by
  obtain ⟨trace, traceEq, messages, fppTarget, piopTarget, decsTarget⟩ :=
    current_causal_payloads_and_targets_of_stages ns dsl statement pending nonce wire
      oracle transcript execution pcs records collisionFree openingRecorded finalRecorded
      hashRecordRetained
  have decsOutput := executed_clean_post_merkle_actual_decs_coefficients
    ns oracle pcs.merkleInput pcs.post pcs.postExecuted coefficientsClean
  have piopOutput := execution_piop_matrix_is_actual_role_output
    ns dsl statement pending statement.toBytes
    (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
    nonce wire oracle transcript execution transcriptClean
  have openingOutput := execution_stages_canonical_raw_opening
    ns dsl statement pending statement.toBytes
    (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
    nonce wire oracle transcript execution openingClean
  let model := SmzaRp05RelationRefinement.relationModel dsl certificates
  refine ⟨trace, traceEq, messages, ?_⟩
  constructor
  · change currentOracleDecodedAt model oracle statement .decsMatrix
      (V8SmzaOracleParser.digestAt messages.fpp.bytes 0) =
      some (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
    simpa only [currentOracleDecodedAt, currentOracleAllAdvice, RoleOutput,
      model, SmzaRp05RelationRefinement.relationModel, fppTarget] using decsOutput
  · change currentOracleDecodedAt model oracle statement .decsMatrix
      (V8SmzaOracleParser.digestAt messages.fpp.bytes 0) =
      some (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
    simpa only [currentOracleDecodedAt, currentOracleAllAdvice, RoleOutput,
      model, SmzaRp05RelationRefinement.relationModel, fppTarget] using decsOutput
  · change currentOracleDecodedAt model oracle statement .piopMatrix
      (V8SmzaOracleParser.digestAt messages.piop.bytes 0) = some execution.matrix
    simpa only [currentOracleDecodedAt, currentOracleAllAdvice, RoleOutput,
      model, SmzaRp05RelationRefinement.relationModel, piopTarget] using piopOutput
  · change currentOracleDecodedAt model oracle statement .decsMatrix
      (V8SmzaOracleParser.digestAt messages.fpp.bytes 0) =
      some (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
    simpa only [currentOracleDecodedAt, currentOracleAllAdvice, RoleOutput,
      model, SmzaRp05RelationRefinement.relationModel, fppTarget] using decsOutput
  · change currentOracleDecodedAt model oracle statement .piopOpening
      (V8SmzaOracleParser.digestAt messages.decs.bytes 0) = some execution.opening
    simpa only [currentOracleDecodedAt, currentOracleAllAdvice, RoleOutput,
      model, SmzaRp05RelationRefinement.relationModel, decsTarget] using openingOutput

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedEarlierAdvice
