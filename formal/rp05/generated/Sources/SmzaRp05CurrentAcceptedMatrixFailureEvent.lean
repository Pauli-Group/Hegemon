import SmzaRp05CurrentAcceptedMatrixEventReadback
import SmzaRp05CurrentAcceptedDecsOutputBinding
import SmzaRp05CurrentAcceptedRoleQueryReadback
import SmzaRp05CurrentDecsGroupedTarget
import SmzaRp05CurrentAcceptedNonleafRoleReadback
import SmzaRp05CurrentAcceptedFilteredRoleTraces
import SmzaRp05CurrentGroupedVerifierReplay
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05CurrentGroupedContext
import SmzaRp05CurrentGroupedRoutes
import SmzaRp05ConcreteSuffix
import SmzaRp05ChallengeRecordErasure

/-! # Actual accepted DECS-matrix event from one execution

This joins the concrete counter-zero DECS call, grouped storage, filtered
readbacks, and the current decoder's bad-matrix result into the role event.
The grouped key, stored vector, and parsed role query are derived from the
same branch's answer log.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedMatrixFailureEvent

open scoped Classical
open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchKeys branchAnswers branchClaims branchResult)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05GroupedSuffix (groupRepresentative groupZero GroupCounter)
open SmzaRp05ExecutablePcsClosure (ExecutionStages transcriptProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05ExecutablePcsClosureSampling
open SmzaRp05ExecutableMerkleVerifier (recordedAttempt)
open SmzaRp05PhysicalPcsRecordRetention (execution_pcs_records_retained_in_verifier)
open SmzaRp05PhysicalHashFppRecordRetention (execution_hash_fpp_records_retained_in_verifier)
open SmzaRp05CurrentGroupedVerifierReplay (accepted_grouped_claims_supply_verifier_replay)
open SmzaRp05CurrentAcceptedDecsOutputBinding (same_stage_decs_counter_zero_decodes)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05CurrentDecsGroupedTarget (recorded_decs_call_has_grouped_target)
open SmzaRp05CurrentAcceptedNonleafRoleReadback (accepted_stages_raw_nonleaf_outer_preambles)
open SmzaRp05CurrentAcceptedFilteredRoleTraces (current_stages_supply_filtered_role_traces)
open SmzaRp05CurrentAcceptedMatrixEventReadback
  (current_matrix_role_event_of_execution_readbacks
    current_matrix_bad_from_challenge_erased_records)
open SmzaRp05CurrentMatrixRoleEvent
  (currentMatrixRoleEvent406)
open SmzaRp05CurrentRoleLabels (currentOuter targetOfRaw currentRawInputDecidableEq)
open SmzaRp05TracePrefixes (RelationModel TypedRoutes AllEarlierTables rootOracle)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords global_extract_filtered_erase_challenge)
open SmzaRp04StatementRecordFilter (oneStatementFilter nonleafFilter)
open SmzaRecordedTracePath (RecordsCollisionFree)
open HegemonCrypto.SmallWood.SmzaChallengeStageTargets (StageQuery parseStageQuery)
open SmzaRp05CurrentUniversalMatrixLoss (currentMatrixBad)
open SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients)
open SmzaRp05PcsHashFppMiddle (gammaRows)
open V8Smz9CoherentMerkleGeometry (extract)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05CurrentAcceptedFilteredRoleTraces (currentOuterTarget)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open V8SmzaOracleParser (RawDigest RawInput)
open HegemonCrypto.SmallWoodTranscript (decsCoefficientDomain)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local instance : DecidableEq RawInput := currentRawInputDecidableEq
local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

set_option maxHeartbeats 1000000 in
/-- From one accepted execution's successful DECS matrix result, construct
the actual current-map matrix role event. The counter-zero call, grouped
storage cell, and role target are recovered from this branch's answer log;
outer and inner traces use the same database and stages. -/
theorem accepted_execution_matrix_bad_yields_role_event
    (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace) (dsl : RelationDsl)
    (statement : Statement) (pending : Bool) (nonce : Fin (2 ^ 32))
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
        (branchKeys (encode (producer.bind fun wire =>
          verifierProgram ns dsl statement pending nonce wire)) groupedDecode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          branch)
        (branchAnswers (encode (producer.bind fun wire =>
          verifierProgram ns dsl statement pending nonce wire)) groupedDecode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          branch)) database)
    (fallback : RawDigest) [Fintype RawDigest]
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : AllEarlierTables model .decsMatrix)
    (outerFuel innerFuel : Nat) (outerEnough : 28 ≤ outerFuel)
    (innerEnough : 28 ≤ innerFuel) (authorized : Finset (List Byte))
    (fresh : statement.toBytes ∉ authorized)
    (wire : ExistingProofFieldView)
    (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback) transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths
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
      (oneStatementFilter (globalLeafStatement ns) statement.toBytes
        (eraseChallengeRecords
          (rawRecords (fun key => groupRepresentative
            (included (producer.bind fun wire =>
              verifierProgram ns dsl statement pending nonce wire) key))
            (vectorOutputBytes groupZero) database))))
    (matrixBad : currentMatrixBad
      (SmzaQ38McaSourceBinding.oracleData
        (rootOracle ns (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes
            (eraseChallengeRecords
              (rawRecords (fun key => groupRepresentative
                (included (producer.bind fun wire =>
                  verifierProgram ns dsl statement pending nonce wire) key))
                (vectorOutputBytes groupZero) database)))
          innerFuel .root pcs.post.root)))
      (SmzaQ38McaSourceBinding.oracleMasks
        (rootOracle ns (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes
            (eraseChallengeRecords
              (rawRecords (fun key => groupRepresentative
                (included (producer.bind fun wire =>
                  verifierProgram ns dsl statement pending nonce wire) key))
                (vectorOutputBytes groupZero) database)))
          innerFuel .root pcs.post.root)))
      (sampledCoefficients (gammaRows pcs.post))) :
    currentMatrixRoleEvent406 model ns
      (fun key => groupRepresentative
        (included (producer.bind fun wire =>
          verifierProgram ns dsl statement pending nonce wire) key))
      groupZero (currentGroupedRoutes model bounded)
      advice outerFuel innerFuel authorized database := by
  classical
  let program := producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire
  let fullRecords := rawRecords
    (fun key => groupRepresentative (included program key))
    (vectorOutputBytes groupZero) database
  let erasedRecords := eraseChallengeRecords fullRecords
  let filteredRecords := oneStatementFilter (globalLeafStatement ns)
    statement.toBytes erasedRecords
  obtain ⟨replayWire, producerSuccess₂, _verifierAccepted₂, retained⟩ :=
    accepted_grouped_claims_supply_verifier_replay
    producer ns dsl statement pending nonce branch accepted database claims fallback
  have sameWire : wire = replayWire := Option.some.inj
    (producerSuccess.symm.trans producerSuccess₂)
  subst replayWire
  have decsDecoded := same_stage_decs_counter_zero_decodes producer ns dsl statement
    pending nonce branch database claims fallback model bounded wire transcript execution
    producerSuccess pcs verifierAccepted transcriptSuccess
  have _acceptedBranch : branchResult groupedDecode program branch = some () := decsDecoded.1
  obtain ⟨vector, callRecorded, decoderRead⟩ := decsDecoded.2
  let callInput := SmzaRp05ExecutableChallengeStage.counterInput
    decsCoefficientDomain pcs.post.root 0
  have groupedTarget := recorded_decs_call_has_grouped_target program branch
    (callInput, vector) callRecorded pcs.post.root ⟨0, by decide⟩ rfl
  obtain ⟨_rolePrefix, keyIdentity, representativeParsed, targetRead⟩ := groupedTarget
  have representativeParsedAtKey : parseStageQuery
      (groupRepresentative (included program (encode program callInput))) =
      some ⟨.decsMatrix, pcs.post.root, 0, 0⟩ := by
    rw [keyIdentity]
    exact representativeParsed
  have roleRead := current_actual_grouped_role_call_readback program branch
    (callInput, vector) callRecorded database claims fallback .decsMatrix
    ⟨.decsMatrix, pcs.post.root, 0, 0⟩ representativeParsedAtKey rfl rfl
  obtain ⟨_rolePrefix, _keyIdentity, _representativeParsed, _coordinates,
    _target, stored, _answer, _allAnswers⟩ := roleRead
  have retainedOuter := accepted_stages_raw_nonleaf_outer_preambles
    producer ns dsl statement pending nonce database fallback wire transcript execution pcs
    verifierAccepted transcriptSuccess outerFuel outerEnough collisionFree retained
  have filteredTraces := current_stages_supply_filtered_role_traces
    producer ns dsl statement pending nonce database fallback wire transcript execution pcs
    verifierAccepted transcriptSuccess innerFuel innerEnough collisionFree retained
  let keyBytes := fun key : Key program => groupRepresentative (included program key)
  have outerReadback : currentOuter ns keyBytes .decsMatrix outerFuel
      (nonleafFilter (globalLeafStatement ns) fullRecords) (encode program callInput) =
        some statement.toBytes := by
    unfold currentOuter
    change SmzaRp05CurrentRoleLabels.preambleFromTrace ns .decsMatrix
      (extract (globalOnlineNext ns) (nonleafFilter (globalLeafStatement ns) fullRecords)
        outerFuel (targetOfRaw .decsMatrix (keyBytes (encode program callInput))).1
        (targetOfRaw .decsMatrix (keyBytes (encode program callInput))).2) = _
    rw [targetRead]
    simpa only [program, fullRecords,
      SmzaRp05CurrentAcceptedFilteredRoleTraces.currentOuterTarget,
      SmzaChallengeStageTargets.roleStage] using retainedOuter .decsMatrix
  have filteredEraseEq := global_extract_filtered_erase_challenge ns fullRecords
    (fun input => globalLeafStatement ns input = none ∨
      globalLeafStatement ns input = some statement.toBytes)
    innerFuel .root pcs.post.root
  have innerReadback : extract (globalOnlineNext ns)
      (oneStatementFilter (globalLeafStatement ns) statement.toBytes fullRecords)
      innerFuel .root pcs.post.root =
      SmzaRp05AcceptedRoleLabels.causalTrace
        (extract (globalOnlineNext ns) filteredRecords innerFuel .decs pcs.openingDigest)
        .decsMatrix := by
    calc
      extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes fullRecords)
          innerFuel .root pcs.post.root =
        extract (globalOnlineNext ns) filteredRecords innerFuel .root pcs.post.root :=
          filteredEraseEq.symm
      _ = SmzaRp05AcceptedRoleLabels.causalTrace
          (extract (globalOnlineNext ns) filteredRecords innerFuel .decs pcs.openingDigest)
          .decsMatrix := by
            simpa only [program, filteredRecords, erasedRecords, fullRecords,
              SmzaRp05CurrentAcceptedFilteredRoleTraces.currentOuterTarget]
              using filteredTraces.2 .decsMatrix
  have rawMatrixBad := current_matrix_bad_from_challenge_erased_records
    ns statement fullRecords innerFuel pcs.post.root
    (sampledCoefficients (gammaRows pcs.post)) matrixBad
  have rootReadback := congrArg (rootOracle ns) innerReadback
  have rawMatrixBadOnTrace := rootReadback ▸ rawMatrixBad
  exact current_matrix_role_event_of_execution_readbacks
    model ns keyBytes groupZero
    (currentGroupedRoutes model bounded)
    advice outerFuel innerFuel authorized statement fresh
    (encode program callInput) vector database
    ⟨.decsMatrix, pcs.post.root, 0, 0⟩
    representativeParsedAtKey
    rfl stored outerReadback
    (extract (globalOnlineNext ns) filteredRecords innerFuel .decs pcs.openingDigest)
    innerReadback (sampledCoefficients (gammaRows pcs.post)) decoderRead rawMatrixBadOnTrace

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedMatrixFailureEvent
