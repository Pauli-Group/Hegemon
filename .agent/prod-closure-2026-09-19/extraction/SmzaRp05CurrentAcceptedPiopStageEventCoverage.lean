import SmzaRp05CurrentAcceptedPiopFailureEvents
import SmzaRp05CurrentAcceptedPiopRecordedOutputs
import SmzaRp05CurrentAcceptedRoleQueryReadback
import SmzaRp05CurrentAcceptedNonleafRoleReadback
import SmzaRp05CurrentAcceptedFilteredRoleTraces
import SmzaRp05CurrentAcceptedEarlierAdvice
import SmzaRp05CurrentGroupedVerifierReplay
import SmzaRp05CurrentGroupedContext
import SmzaRp05CurrentAcceptedPiopOutputBinding
import SmzaRp05CurrentCausalNonchallengeRetention
import SmzaRp05ChallengeRecordErasure

/-! # Same-stage accepted PIOP event coverage

This adapter takes one accepted grouped execution and genuine causal
`EarlierReadback` data. The PIOP vectors and grouped cells are reconstructed
from that branch's answer log; raw and filtered trace readbacks are derived
from the same execution and database.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopStageEventCoverage

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
open SmzaRp05CurrentAcceptedPiopRecordedOutputs
  (accepted_matrix_call_and_vector accepted_opening_call_and_vector)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05CurrentAcceptedPiopOutputBinding (actual_grouped_piop_matrix_route_output)
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
    (failure :
      ((¬ HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
          ((relationModel dsl certificates).recoveredCandidate statement source.data).system) ∧
        execution.matrix ∈ SmzaRp04ChronologicalAlgebra.piopMatrixBadEvent
          ((relationModel dsl certificates).recoveredCandidate statement source.data)) ∨
      execution.opening ∈ SmzaRp04ChronologicalAlgebra.piopOpeningBadEvent
        ((relationModel dsl certificates).recoveredCandidate statement source.data) execution.matrix
        (SmzaRp05TracePrefixes.piopResponse messages.piop)) :
    currentPiopRoleEvent406 (relationModel dsl certificates) ns
      (fun key => groupRepresentative
        (included (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) key))
      groupZero (currentGroupedRoutes (relationModel dsl certificates) bounded) .matrix
      (advice .piopMatrix)
      outerFuel 28 authorized database ∨
    currentPiopRoleEvent406 (relationModel dsl certificates) ns
      (fun key => groupRepresentative
        (included (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) key))
      groupZero (currentGroupedRoutes (relationModel dsl certificates) bounded) .opening
      (advice .piopOpening)
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
          some statement.toBytes := by
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
    exact Or.inl (current_piop_event_of_readbacks model ns keyBytes groupZero
      (currentGroupedRoutes model bounded) .matrix
      (advice .piopMatrix) outerFuel 28 authorized statement fresh
      (encode program callInput) vector database query representativeParsed rfl stored
      outerReadback actualTrace innerReadback labelBad)
  · obtain ⟨counter, vector, counterBound, recorded, sampled⟩ :=
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
      simpa only [program, fullRecords, currentOuterTarget,
        SmzaRp05CurrentAcceptedFilteredRoleTraces.currentOuterTarget,
        SmzaChallengeStageTargets.roleStage] using
        retainedOuter .piopOpening
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
    exact Or.inr (current_piop_event_of_readbacks model ns keyBytes groupZero
      (currentGroupedRoutes model bounded) .opening
      (advice .piopOpening) outerFuel 28 authorized statement fresh
      (encode program callInput) vector database ⟨.piopOpening, wire.hPiop, nonce.val, 0⟩
      representativeParsed rfl stored outerReadback actualTrace innerReadback labelBad)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopStageEventCoverage
