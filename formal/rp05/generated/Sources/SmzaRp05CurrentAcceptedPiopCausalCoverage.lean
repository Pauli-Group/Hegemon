import SmzaRp05CurrentAcceptedPiopClassifierCoverage
import SmzaRp05CurrentCausalNonchallengeRetention
import SmzaRp05CurrentAcceptedCausalPayloads
import SmzaRp05CurrentAcceptedXViewRoleCoverage
import SmzaRp05CurrentFppFrameReadback
import SmzaRp05ChallengeRoleSeparation

/-! # Same-stage classifier failure on its causal trace -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopCausalCoverage

open HegemonCrypto.CanonicalBytes (Byte encodeLE)
open SmzaRp05CurrentAcceptedPiopClassifierCoverage
  (classified_piop_failure_transports_to_causal_trace)
open SmzaRp05CurrentCausalNonchallengeRetention
  (accepted_execution_causal_record_memberships)
open SmzaRp05CurrentAcceptedCausalPayloads
  (Records current_causal_payloads_and_targets_of_stages)
open SmzaRp05CurrentAcceptedXViewRoleCoverage (noWitnessRoleFailure)
open SmzaRp05CurrentFppFrameReadback (successful_response_program_has_current_fpp_edge)
open SmzaRp05ExecutableMerkleVerifier (Oracle Program ask)
open SmzaRp05ExecutablePcsClosure (ExecutionStages transcriptProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureStatement (statementBindingWords verifierProgram)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript finalInput)
open SmzaRp05RelationRefinement (RelationDsl relationModel)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentDecsFrameReadback (current_decs_opening_edge406)
open SmzaRp05CurrentPiopFrameReadback (current_final_normalized_payload current_final_piop_edge)
open SmzaRp05PcsToFinalProgram (sameProofRows)
open SmzaRp05PcsHashFppMiddle (gammaRows)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp04StatementRecordFilter (oneStatementFilter)
open SmzaRp05FilteredDecoderInstability (globalNormalizedPayload globalOnlineNext)
open SmzaRp05AcceptedRoleLabels
  (causalTrace current_inner_readback_of_recorded_chain)
open SmzaChallengeStageTargets (Role parseStageQuery)
open V8Smz9CoherentMerkleGeometry (extract)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8SmzaOracleParser (RawDigest RawInput Payload)
open SmzaRecordedTracePath (RecordsCollisionFree)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 24000
set_option maxHeartbeats 1600000
attribute [local instance] Classical.propDecidable

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local instance : DecidableEq RawInput := SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq
local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

private theorem nonleaf_call_survives_filtered_view
    (ns : Namespace) (statement : Statement) (fullRecords filteredRecords : Records)
    (input : RawInput) (output : RawDigest) (payload : Payload)
    (normalized : globalNormalizedPayload ns input = some payload)
    (notLeaf : payload.kind ≠ .leaf) (fullMember : (input, output) ∈ fullRecords)
    (filteredEq : filteredRecords = oneStatementFilter (globalLeafStatement ns)
      statement.toBytes (eraseChallengeRecords fullRecords)) :
    (input, output) ∈ filteredRecords := by
  have queryNone : parseStageQuery input = none := by
    cases parsed : parseStageQuery input with
    | none => rfl
    | some query =>
        have impossible := SmzaRp05ChallengeRecordErasure.parse_stage_query_global_payload_none
          ns input query parsed
        rw [normalized] at impossible
        cases impossible
  have erasedMember : (input, output) ∈ eraseChallengeRecords fullRecords := by
    exact Finset.mem_filter.mpr ⟨fullMember, by simp [queryNone]⟩
  have leafNone : globalLeafStatement ns input = none := by
    cases framed : V8SmzaOracleParser.parseFramed input with
    | none => simp [SmzaRp05FilteredReadback.globalLeafStatement, framed]
    | some frame =>
        rcases frame with ⟨stage, bytes⟩
        let salt := (bytes.drop SmzaRp05LeafNamespace.preambleBytes).take 32
        have normalizedRead : SmzaRp05LeafNamespace.normalizedPayload ns salt input =
            some payload := by
          simpa [globalNormalizedPayload, framed, salt] using normalized
        cases leaf : SmzaRp05LeafNamespace.parseCurrentLeaf ns salt input with
        | none =>
            have noneLeaf : SmzaRp05LeafNamespace.leafStatement ns salt input = none := by
              simp [SmzaRp05LeafNamespace.leafStatement, leaf]
            unfold SmzaRp05FilteredReadback.globalLeafStatement
            simp only [framed]
            simpa [salt] using noneLeaf
        | some currentLeaf =>
            have payloadEq : payload = currentLeaf.normalized := by
              have h : some currentLeaf.normalized = some payload := by
                simpa [SmzaRp05LeafNamespace.normalizedPayload, leaf] using normalizedRead
              exact (Option.some.inj h).symm
            have kindEq : payload.kind = .leaf := by rw [payloadEq]; rfl
            exact (notLeaf kindEq).elim
  rw [filteredEq]
  exact Finset.mem_filter.mpr ⟨erasedMember, Or.inl leafNone⟩

private theorem same_execution_filtered_causal_calls
    (ns : Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns SmzaRp05GeneratedCertificates.currentDsl
      statement pending statement.toBytes (statementBindingWords statement)
      nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (sameProofRows execution.middle.pcs execution.piop) execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement) wire.tapes
      wire.paths oracle execution.hashFpp execution.pcsPending)
    [Fintype RawDigest] (fullRecords : Records)
    (verifierAccepted : (verifierProgram ns SmzaRp05GeneratedCertificates.currentDsl
      statement pending nonce wire).eval oracle = some ())
    (transcriptSuccess : (transcriptProgram ns SmzaRp05GeneratedCertificates.currentDsl
      statement pending statement.toBytes (statementBindingWords statement) nonce wire).eval
        oracle = some transcript)
    (nonchallengeRetained : ∀ call,
      call ∈ ((verifierProgram ns SmzaRp05GeneratedCertificates.currentDsl
        statement pending nonce wire).record oracle).2 →
      parseStageQuery call.1 = none → call ∈ fullRecords)
    (input : RawInput) (inputRecorded : (input, execution.hashFpp) ∈
      (pcs.hashProgram.record oracle).2)
    :
    let filtered := oneStatementFilter (globalLeafStatement ns) statement.toBytes
      (eraseChallengeRecords fullRecords)
    (pcs.openingInput, pcs.openingDigest) ∈ filtered ∧
      (finalInput transcript, wire.hPiop) ∈ filtered ∧
      (∀ call, call ∈ (pcs.hashProgram.record oracle).2 → call ∈ filtered) := by
  classical
  let filtered := oneStatementFilter (globalLeafStatement ns) statement.toBytes
    (eraseChallengeRecords fullRecords)
  obtain ⟨openingFull, finalFull, hashFull⟩ :=
    accepted_execution_causal_record_memberships ns
      SmzaRp05GeneratedCertificates.currentDsl statement pending nonce wire oracle
      transcript execution pcs fullRecords verifierAccepted transcriptSuccess
      nonchallengeRetained
  obtain ⟨decsRows, _rows, _framed, decsNormalized, _next⟩ :=
    current_decs_opening_edge406 ns wire.hPiop pcs.heads
      execution.middle.pcs.rcombiTails pcs.openingInput pcs.openingBuilt
  have piopNormalized := current_final_normalized_payload ns transcript
  have openingFiltered := nonleaf_call_survives_filtered_view ns statement fullRecords
    filtered pcs.openingInput pcs.openingDigest
    ⟨.decs, ((SmzaRp05ExecutableChallengeStage.digestWords wire.hPiop ++ decsRows).flatMap
      (encodeLE 8))⟩ decsNormalized
    (by change V8SmzaOracleParser.Kind.decs ≠ V8SmzaOracleParser.Kind.leaf; decide)
    openingFull rfl
  have finalFiltered := nonleaf_call_survives_filtered_view ns statement fullRecords
    filtered (finalInput transcript) wire.hPiop
    ⟨.piop, SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩
    piopNormalized
    (by change V8SmzaOracleParser.Kind.piop ≠ V8SmzaOracleParser.Kind.leaf; decide)
    finalFull rfl
  obtain ⟨selectedInput, fppBytes, selectedAsk, _framed, fppNormalized, _next, _suffix⟩ :=
    successful_response_program_has_current_fpp_edge ns pcs.post.root execution.decs
      (pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      (gammaRows pcs.post)
      (pcs.decsPoints.map fun point => SmzaRp05ExecutableRestore.toWord point)
      (statementBindingWords statement)
      (SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement)
      pcs.hashProgram pcs.responseBuilt
  have fppValue : oracle selectedInput = execution.hashFpp := by
    have executed := pcs.hashExecuted
    rw [selectedAsk] at executed
    simpa [ask, SmzaRp05ExecutableMerkleVerifier.Program.eval] using executed
  have hashLogEq : (pcs.hashProgram.record oracle).2 =
      [(selectedInput, execution.hashFpp)] := by
    rw [selectedAsk]
    simp [ask, SmzaRp05ExecutableMerkleVerifier.Program.record, fppValue]
  have inputEq : input = selectedInput := by
    rw [hashLogEq] at inputRecorded
    simpa using inputRecorded
  have selectedNormalized := fppNormalized
  have selectedFull : (selectedInput, execution.hashFpp) ∈ fullRecords := by
    have fromInput := hashFull (input, execution.hashFpp) inputRecorded
    simpa [inputEq] using fromInput
  have selectedFiltered := nonleaf_call_survives_filtered_view ns statement fullRecords
    filtered selectedInput execution.hashFpp ⟨.fpp, fppBytes⟩ selectedNormalized
    (by change V8SmzaOracleParser.Kind.fpp ≠ V8SmzaOracleParser.Kind.leaf; decide)
    selectedFull rfl
  refine ⟨openingFiltered, finalFiltered, ?_⟩
  intro call member
  rw [hashLogEq] at member
  have callEq : call = (selectedInput, execution.hashFpp) := by simpa using member
  simpa [callEq] using selectedFiltered

set_option linter.constructorNameAsVariable false in
/-- The classifier's PIOP failure projection for an already selected successful
execution transports to the causal trace of that same execution. -/
theorem same_stage_piop_failure_has_causal_readback
    (role : SmzaRp05CurrentPiopRoleEvents.PiopRole)
    (ns : Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns SmzaRp05GeneratedCertificates.currentDsl
      statement pending statement.toBytes (statementBindingWords statement)
      nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (sameProofRows execution.middle.pcs execution.piop) execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement) wire.tapes
      wire.paths oracle execution.hashFpp execution.pcsPending)
    [Fintype RawDigest] (fullRecords : Records)
    (verifierAccepted : (verifierProgram ns SmzaRp05GeneratedCertificates.currentDsl
      statement pending nonce wire).eval oracle = some ())
    (transcriptSuccess : (transcriptProgram ns SmzaRp05GeneratedCertificates.currentDsl
      statement pending statement.toBytes (statementBindingWords statement) nonce wire).eval
        oracle = some transcript)
    (nonchallengeRetained : ∀ call,
      call ∈ ((verifierProgram ns SmzaRp05GeneratedCertificates.currentDsl
        statement pending nonce wire).record oracle).2 →
      parseStageQuery call.1 = none → call ∈ fullRecords)
    (collisionFree : RecordsCollisionFree
      (oneStatementFilter (globalLeafStatement ns) statement.toBytes
        (eraseChallengeRecords fullRecords)))
    (input : RawInput) (query : SmzaRp05CurrentMaxAgreementRecovery.Query)
    (inputRecorded : (input, execution.hashFpp) ∈ (pcs.hashProgram.record oracle).2)
    (failure : noWitnessRoleFailure role.toRole ns statement pending nonce wire oracle
      transcript execution pcs (eraseChallengeRecords fullRecords) 28 input query) :
    ∃ messages : SmzaRp05AcceptedRoleLabels.CausalPayloads ns
      (extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes
          (eraseChallengeRecords fullRecords)) 28 .decs pcs.openingDigest),
      ∃ _openingRecorded : (pcs.openingInput, pcs.openingDigest) ∈
        oneStatementFilter (globalLeafStatement ns) statement.toBytes
          (eraseChallengeRecords fullRecords),
      ∃ _finalRecorded : (finalInput transcript, wire.hPiop) ∈
        oneStatementFilter (globalLeafStatement ns) statement.toBytes
          (eraseChallengeRecords fullRecords),
      ∃ _hashRetained : ∀ call, call ∈ (pcs.hashProgram.record oracle).2 →
        call ∈ oneStatementFilter (globalLeafStatement ns) statement.toBytes
          (eraseChallengeRecords fullRecords),
      ∃ _rootTraceEq : extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes
          (eraseChallengeRecords fullRecords)) 28 .root pcs.post.root =
          SmzaRp05AcceptedRoleLabels.causalTrace
            (extract (globalOnlineNext ns)
              (oneStatementFilter (globalLeafStatement ns) statement.toBytes
                (eraseChallengeRecords fullRecords)) 28 .decs pcs.openingDigest) .decsMatrix,
      ∃ _piopTraceEq : extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes
          (eraseChallengeRecords fullRecords)) 28 .piop wire.hPiop =
          SmzaRp05AcceptedRoleLabels.causalTrace
            (extract (globalOnlineNext ns)
              (oneStatementFilter (globalLeafStatement ns) statement.toBytes
                (eraseChallengeRecords fullRecords)) 28 .decs pcs.openingDigest) .piopOpening,
      (match role with
      | .matrix =>
          ∃ source : V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140,
            SmzaRp05CurrentTracePrefixes406.currentSourceDecoder406
              (SmzaRp05AcceptedRoleLabels.causalOracle ns
                (extract (globalOnlineNext ns)
                  (oneStatementFilter (globalLeafStatement ns) statement.toBytes
                    (eraseChallengeRecords fullRecords)) 28 .decs pcs.openingDigest))
              messages.fpp
              (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients (gammaRows pcs.post)) =
                some source ∧
            ¬ HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
              ((relationModel SmzaRp05GeneratedCertificates.currentDsl
                SmzaRp05GeneratedCertificates.certificates).recoveredCandidate
                statement source.data).system ∧
            execution.matrix ∈ SmzaRp04ChronologicalAlgebra.piopMatrixBadEvent
              ((relationModel SmzaRp05GeneratedCertificates.currentDsl
                SmzaRp05GeneratedCertificates.certificates).recoveredCandidate
                statement source.data)
      | .opening =>
          ∃ source : V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140,
            SmzaRp05CurrentTracePrefixes406.currentSourceDecoder406
              (SmzaRp05AcceptedRoleLabels.causalOracle ns
                (extract (globalOnlineNext ns)
                  (oneStatementFilter (globalLeafStatement ns) statement.toBytes
                    (eraseChallengeRecords fullRecords)) 28 .decs pcs.openingDigest))
              messages.fpp
              (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients (gammaRows pcs.post)) =
                some source ∧
            ¬ HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
              ((relationModel SmzaRp05GeneratedCertificates.currentDsl
                SmzaRp05GeneratedCertificates.certificates).recoveredCandidate
                statement source.data).system ∧
            execution.opening ∈ SmzaRp04ChronologicalAlgebra.piopOpeningBadEvent
              ((relationModel SmzaRp05GeneratedCertificates.currentDsl
                SmzaRp05GeneratedCertificates.certificates).recoveredCandidate
                statement source.data) execution.matrix
              (SmzaRp05TracePrefixes.piopResponse messages.piop)) := by
  classical
  let filteredRecords := oneStatementFilter (globalLeafStatement ns) statement.toBytes
    (eraseChallengeRecords fullRecords)
  rcases role with matrix | opening
  · have matrixFailure : noWitnessRoleFailure .piopMatrix ns statement pending nonce wire
        oracle transcript execution pcs (eraseChallengeRecords fullRecords) 28 input query := by
      simpa [SmzaRp05CurrentPiopRoleEvents.PiopRole.toRole] using failure
    dsimp only [noWitnessRoleFailure] at failure
    rcases failure with ⟨_good, fpp, _openingPayload, _parsed, normalizedInput,
      _suffix, _parsedOpening, _normalizedOpening, _claims, _source, _recovered,
      _rows, _notFull, _bad⟩
    have calls := same_execution_filtered_causal_calls ns statement pending nonce wire
      oracle transcript execution pcs fullRecords verifierAccepted transcriptSuccess
      nonchallengeRetained input inputRecorded
    obtain ⟨openingRecorded, finalRecorded, hashRetained⟩ := calls
    obtain ⟨trace, traceEq, messages, _fppRoot, _piopHash, _decsDigest⟩ :=
      current_causal_payloads_and_targets_of_stages ns
        SmzaRp05GeneratedCertificates.currentDsl statement pending nonce wire oracle
        transcript execution pcs filteredRecords collisionFree openingRecorded
        finalRecorded hashRetained
    let filteredTrace := extract (globalOnlineNext ns) filteredRecords 28
      .decs pcs.openingDigest
    have filteredMessages :
        SmzaRp05AcceptedRoleLabels.CausalPayloads ns filteredTrace := by
      change SmzaRp05AcceptedRoleLabels.CausalPayloads ns
        (extract (globalOnlineNext ns) filteredRecords 28 .decs pcs.openingDigest)
      exact Eq.mp (congrArg (SmzaRp05AcceptedRoleLabels.CausalPayloads ns) traceEq)
        messages
    obtain ⟨decsRows, _rows, _framed, decsNormalized, decsNext⟩ :=
      current_decs_opening_edge406 ns wire.hPiop pcs.heads
        execution.middle.pcs.rcombiTails pcs.openingInput pcs.openingBuilt
    have piopNormalized := current_final_normalized_payload ns transcript
    have piopNext := current_final_piop_edge ns transcript
    have transcriptHash : transcript.hashFpp = execution.hashFpp := by
      have projected := congrArg ReconstructedTranscript.hashFpp execution.reconstructed
      simpa [SmzaRp05ExecutableReconstruction.reconstruct] using projected.symm
    have piopNext' : globalOnlineNext ns .piop (finalInput transcript) =
        some [(.fpp, execution.hashFpp)] := by simpa [transcriptHash] using piopNext
    obtain ⟨selectedInput, _fppBytes, selectedAsk, _framed, _fppNormalized, fppNext, _suffix⟩ :=
      successful_response_program_has_current_fpp_edge ns pcs.post.root execution.decs
        (pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
        (gammaRows pcs.post)
        (pcs.decsPoints.map fun point => SmzaRp05ExecutableRestore.toWord point)
        (statementBindingWords statement)
        (SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement)
        pcs.hashProgram pcs.responseBuilt
    let target : Role → V8SmzaOracleParser.Stage × RawDigest
      | .decsMatrix => (.root, pcs.post.root)
      | .piopMatrix => (.fpp, execution.hashFpp)
      | .piopOpening => (.piop, wire.hPiop)
      | .decsSample => (.decs, pcs.openingDigest)
    have targets : target .decsMatrix = (.root, pcs.post.root) ∧
        target .piopMatrix = (.fpp, execution.hashFpp) ∧
        target .piopOpening = (.piop, wire.hPiop) ∧
        target .decsSample = (.decs, pcs.openingDigest) := ⟨rfl, rfl, rfl, rfl⟩
    have inner := current_inner_readback_of_recorded_chain ns filteredRecords collisionFree
      pcs.openingDigest wire.hPiop execution.hashFpp pcs.post.root
      pcs.openingInput (finalInput transcript) selectedInput openingRecorded finalRecorded
      (by
        have fromInput := hashRetained (input, execution.hashFpp) inputRecorded
        have inputEq : input = selectedInput := by
          rw [selectedAsk] at inputRecorded
          have pairEq : (input, execution.hashFpp) =
              (selectedInput, oracle selectedInput) := by
            simpa [SmzaRp05ExecutableMerkleVerifier.ask,
              SmzaRp05ExecutableMerkleVerifier.Program.record] using inputRecorded
          change input = selectedInput
          exact congrArg Prod.fst pairEq
        simpa [inputEq] using fromInput)
      decsNext piopNext' fppNext 28 (by decide) target targets
    have rootTraceEq := inner .decsMatrix
    have piopTraceEq := inner .piopOpening
    refine ⟨filteredMessages, openingRecorded, finalRecorded, hashRetained,
      rootTraceEq, piopTraceEq, ?_⟩
    exact classified_piop_failure_transports_to_causal_trace .matrix ns statement pending nonce
      wire oracle transcript execution pcs (eraseChallengeRecords fullRecords) 28 input query
      (extract (globalOnlineNext ns) filteredRecords 28 .decs pcs.openingDigest)
      filteredMessages collisionFree inputRecorded openingRecorded finalRecorded hashRetained rfl
      rootTraceEq piopTraceEq matrixFailure
  · have openingFailure : noWitnessRoleFailure .piopOpening ns statement pending nonce wire
        oracle transcript execution pcs (eraseChallengeRecords fullRecords) 28 input query := by
      simpa [SmzaRp05CurrentPiopRoleEvents.PiopRole.toRole] using failure
    dsimp only [noWitnessRoleFailure] at failure
    rcases failure with ⟨_good, fpp, _openingPayload, _parsed, normalizedInput,
      _suffix, _parsedOpening, _normalizedOpening, _claims, _source, _recovered,
      _rows, _notFull, _bad⟩
    have calls := same_execution_filtered_causal_calls ns statement pending nonce wire
      oracle transcript execution pcs fullRecords verifierAccepted transcriptSuccess
      nonchallengeRetained input inputRecorded
    obtain ⟨openingRecorded, finalRecorded, hashRetained⟩ := calls
    obtain ⟨trace, traceEq, messages, _fppRoot, _piopHash, _decsDigest⟩ :=
      current_causal_payloads_and_targets_of_stages ns
        SmzaRp05GeneratedCertificates.currentDsl statement pending nonce wire oracle
        transcript execution pcs filteredRecords collisionFree openingRecorded
        finalRecorded hashRetained
    let filteredTrace := extract (globalOnlineNext ns) filteredRecords 28
      .decs pcs.openingDigest
    have filteredMessages :
        SmzaRp05AcceptedRoleLabels.CausalPayloads ns filteredTrace := by
      change SmzaRp05AcceptedRoleLabels.CausalPayloads ns
        (extract (globalOnlineNext ns) filteredRecords 28 .decs pcs.openingDigest)
      exact Eq.mp (congrArg (SmzaRp05AcceptedRoleLabels.CausalPayloads ns) traceEq)
        messages
    obtain ⟨decsRows, _rows, _framed, decsNormalized, decsNext⟩ :=
      current_decs_opening_edge406 ns wire.hPiop pcs.heads
        execution.middle.pcs.rcombiTails pcs.openingInput pcs.openingBuilt
    have piopNext := current_final_piop_edge ns transcript
    have transcriptHash : transcript.hashFpp = execution.hashFpp := by
      have projected := congrArg ReconstructedTranscript.hashFpp execution.reconstructed
      simpa [SmzaRp05ExecutableReconstruction.reconstruct] using projected.symm
    have piopNext' : globalOnlineNext ns .piop (finalInput transcript) =
        some [(.fpp, execution.hashFpp)] := by simpa [transcriptHash] using piopNext
    obtain ⟨selectedInput, _fppBytes, selectedAsk, _framed, _fppNormalized, fppNext, _suffix⟩ :=
      successful_response_program_has_current_fpp_edge ns pcs.post.root execution.decs
        (pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
        (gammaRows pcs.post)
        (pcs.decsPoints.map fun point => SmzaRp05ExecutableRestore.toWord point)
        (statementBindingWords statement)
        (SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement)
        pcs.hashProgram pcs.responseBuilt
    let target : Role → V8SmzaOracleParser.Stage × RawDigest
      | .decsMatrix => (.root, pcs.post.root)
      | .piopMatrix => (.fpp, execution.hashFpp)
      | .piopOpening => (.piop, wire.hPiop)
      | .decsSample => (.decs, pcs.openingDigest)
    have targets : target .decsMatrix = (.root, pcs.post.root) ∧
        target .piopMatrix = (.fpp, execution.hashFpp) ∧
        target .piopOpening = (.piop, wire.hPiop) ∧
        target .decsSample = (.decs, pcs.openingDigest) := ⟨rfl, rfl, rfl, rfl⟩
    have inner := current_inner_readback_of_recorded_chain ns filteredRecords collisionFree
      pcs.openingDigest wire.hPiop execution.hashFpp pcs.post.root
      pcs.openingInput (finalInput transcript) selectedInput openingRecorded finalRecorded
      (by
        have fromInput := hashRetained (input, execution.hashFpp) inputRecorded
        have inputEq : input = selectedInput := by
          rw [selectedAsk] at inputRecorded
          have pairEq : (input, execution.hashFpp) =
              (selectedInput, oracle selectedInput) := by
            simpa [SmzaRp05ExecutableMerkleVerifier.ask,
              SmzaRp05ExecutableMerkleVerifier.Program.record] using inputRecorded
          change input = selectedInput
          exact congrArg Prod.fst pairEq
        simpa [inputEq] using fromInput)
      decsNext piopNext' fppNext 28 (by decide) target targets
    have rootTraceEq := inner .decsMatrix
    have piopTraceEq := inner .piopOpening
    refine ⟨filteredMessages, openingRecorded, finalRecorded, hashRetained,
      rootTraceEq, piopTraceEq, ?_⟩
    exact classified_piop_failure_transports_to_causal_trace .opening ns statement pending nonce
      wire oracle transcript execution pcs (eraseChallengeRecords fullRecords) 28 input query
      (extract (globalOnlineNext ns) filteredRecords 28 .decs pcs.openingDigest)
      filteredMessages collisionFree inputRecorded openingRecorded finalRecorded hashRetained rfl
      rootTraceEq piopTraceEq openingFailure

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopCausalCoverage
