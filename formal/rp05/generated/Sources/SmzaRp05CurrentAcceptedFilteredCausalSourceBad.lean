import SmzaRp05CurrentAcceptedCausalPayloads
import SmzaRp05CurrentCausalNonchallengeRetention
import SmzaRp05CurrentFppRecordFreshness
import SmzaRp05CurrentAcceptedFilteredRoleTraces
import SmzaRp05AcceptedRoleLabels
import SmzaRp05CurrentTracePrefixes406
import SmzaRp05CurrentAcceptedQuerySupport

/-! # Filtered classifier source-bad transport to the same causal trace

This bridge identifies the classifier's filtered root, FPP payload, and DECS
coefficient payload with the causal chain read from the very same accepted
stages.  It uses actual stage-record retention plus nonleaf freshness; it does
not equate unfiltered and filtered extraction trees.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFilteredCausalSourceBad

open scoped Classical
open HegemonCrypto.CanonicalBytes (Byte encodeLE)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle ask)
open SmzaRp05ExecutablePcsClosure (ExecutionStages transcriptProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureStatement (statementBindingWords verifierProgram)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentAcceptedCausalPayloads
  (Records current_causal_payloads_and_targets_of_stages)
open SmzaRp05CurrentCausalNonchallengeRetention
  (accepted_execution_causal_record_memberships)
open SmzaRp05CurrentDecsFrameReadback (current_decs_opening_edge406)
open SmzaRp05CurrentPiopFrameReadback (current_final_normalized_payload current_final_piop_edge)
open SmzaRp05CurrentFppFrameReadback (successful_response_program_has_current_fpp_edge)
open SmzaRp05CurrentFppRecordFreshness (successful_response_hash_records_nonleaf)
open SmzaRp05FilteredDecoderInstability
  (globalNormalizedPayload globalOnlineNext)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords)
open SmzaRp04StatementRecordFilter (oneStatementFilter)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp05AcceptedRoleLabels
  (CausalPayloads causalTrace global_recorded_decs_chain global_recorded_single_child_trace
    global_sufficient_fuel_same_trace
    global_payload_of_recorded_input)
open SmzaRp05CurrentRoleLabels (currentRawInputDecidableEq)
open SmzaRp05TracePrefixes (Trace)
open SmzaChallengeStageTargets (parseStageQuery)
open SmzaRp05PcsHashFppMiddle (gammaRows)
open SmzaRp05PcsToFinalProgram (sameProofRows)
open SmzaRp05TracePrefixes (queryCoefficients)
open HegemonCrypto.SmallWood.SmzaRp05CurrentTracePrefixes406
  (currentSourceBad406 currentSourcePrefix406)
open SmzaRp05CurrentUniversalMatrixLoss (currentMatrixBad)
open SmzaRp05CurrentMaxAgreementRecovery (Coefficients)
open V8Smz9CoherentMerkleGeometry (extract)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1600000
attribute [local instance] Classical.propDecidable

local instance : DecidableEq RawInput := currentRawInputDecidableEq
local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

local notation "Records" => SmzaRp05AcceptedRoleLabels.Records
local notation "Payload" => SmzaRp05TracePrefixes.Payload

private theorem normalized_input_is_nonleaf
    (ns : Namespace) (input : RawInput) (payload : Payload)
    (normalized : globalNormalizedPayload ns input = some payload)
    (notLeaf : payload.kind ≠ .leaf) :
    globalLeafStatement ns input = none := by
  cases framed : V8SmzaOracleParser.parseFramed input with
  | none => simp [globalNormalizedPayload, framed] at normalized
  | some frame =>
      rcases frame with ⟨roleBytes, bytes⟩
      have normalizedRead :
          SmzaRp05LeafNamespace.normalizedPayload ns
            ((bytes.drop SmzaRp05LeafNamespace.preambleBytes).take 32) input =
            some payload := by
        simpa [globalNormalizedPayload, framed] using normalized
      cases leaf : SmzaRp05LeafNamespace.parseCurrentLeaf ns
          ((bytes.drop SmzaRp05LeafNamespace.preambleBytes).take 32) input with
      | none =>
          have leafNone : SmzaRp05LeafNamespace.leafStatement ns
              ((bytes.drop SmzaRp05LeafNamespace.preambleBytes).take 32) input = none := by
            simp [SmzaRp05LeafNamespace.leafStatement, leaf]
          unfold globalLeafStatement
          simp only [framed]
          simpa using leafNone
      | some currentLeaf =>
          have payloadEq : payload = currentLeaf.normalized := by
            have someEq : some currentLeaf.normalized = some payload := by
              simpa [SmzaRp05LeafNamespace.normalizedPayload, leaf] using normalizedRead
            exact (Option.some.inj someEq).symm
          have kindEq : payload.kind = .leaf := by rw [payloadEq]; rfl
          exact (notLeaf kindEq).elim

private theorem retained_nonleaf_survives_current_filter
    (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement)
    (fullRecords filteredRecords : Records)
    (input : RawInput) (output : RawDigest) (payload : Payload)
    (normalized : globalNormalizedPayload ns input = some payload)
    (notLeaf : payload.kind ≠ .leaf)
    (fullMember : (input, output) ∈ fullRecords)
    (filterEq : filteredRecords = oneStatementFilter (globalLeafStatement ns)
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
  have erased : (input, output) ∈ eraseChallengeRecords fullRecords := by
    apply Finset.mem_filter.mpr
    exact ⟨fullMember, by simp only [queryNone]; rfl⟩
  rw [filterEq]
  apply Finset.mem_filter.mpr
  exact ⟨erased, Or.inl (normalized_input_is_nonleaf ns input payload normalized notLeaf)⟩

private theorem current_source_prefix406_congr
    (oracleL oracleR : SmzaQ38OracleExtraction.CommittedOracle)
    (fppL fppR : Payload) (coeffL coeffR : Coefficients)
    (pointsL pointsR : Fin 6 → HegemonCrypto.SmallWood.Goldilocks)
    (claimedL claimedR : SmzaRp04ChronologicalAlgebra.Fixed406Coefficients)
    (goodL : ¬ currentMatrixBad (SmzaQ38McaSourceBinding.oracleData oracleL)
      (SmzaQ38McaSourceBinding.oracleMasks oracleL) coeffL)
    (goodR : ¬ currentMatrixBad (SmzaQ38McaSourceBinding.oracleData oracleR)
      (SmzaQ38McaSourceBinding.oracleMasks oracleR) coeffR)
    (oracleEq : oracleL = oracleR) (fppBytesEq : fppL.bytes = fppR.bytes)
    (coeffEq : coeffL = coeffR) (pointsEq : pointsL = pointsR)
    (claimedEq : claimedL = claimedR) :
    currentSourcePrefix406 oracleL fppL coeffL pointsL claimedL goodL =
      currentSourcePrefix406 oracleR fppR coeffR pointsR claimedR goodR := by
  cases oracleEq
  cases coeffEq
  cases pointsEq
  cases claimedEq
  cases fppL with
  | mk kindL bytesL =>
    cases fppR with
    | mk kindR bytesR =>
      change bytesL = bytesR at fppBytesEq
      subst bytesR
      have goodEq : goodL = goodR := Subsingleton.elim _ _
      cases goodEq
      rfl

/-- A bad source query produced by the filtered current classifier is a bad
query on the matching causal source prefix. The caller supplies only the
classifier's local source-bad arm and actual accepted-stage replay retention;
the trace, three causal records, payload identities, and root equality are
reconstructed here. -/
theorem filtered_classifier_source_bad_to_causal
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (sameProofRows execution.middle.pcs execution.piop) execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending)
    [Fintype RawDigest]
    (fullRecords : Records)
    (filteredRecords : Records)
    (filterEq : filteredRecords = oneStatementFilter (globalLeafStatement ns)
      statement.toBytes (eraseChallengeRecords fullRecords))
    (collisionFree : SmzaRecordedTracePath.RecordsCollisionFree filteredRecords)
    (verifierAccepted : (verifierProgram ns dsl statement pending nonce wire).eval oracle = some ())
    (transcriptSuccess : (transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire).eval oracle = some transcript)
    (nonchallengeRetained : ∀ call,
      call ∈ ((verifierProgram ns dsl statement pending nonce wire).record oracle).2 →
      parseStageQuery call.1 = none → call ∈ fullRecords)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (input : RawInput) (query : SmzaQ38McaSourceBinding.Query)
    (inputRecord : (input, execution.hashFpp) ∈ (pcs.hashProgram.record oracle).2)
    (fpp : Payload) (openingPayload : Payload)
    (inputNormalized : globalNormalizedPayload ns input = some ⟨.fpp, fpp.bytes⟩)
    (openingParsed : V8SmzaOracleParser.parseFramed pcs.openingInput =
      some (SmallWoodTranscript.decsOpeningDomain, openingPayload.bytes))
    (openingNormalized : globalNormalizedPayload ns pcs.openingInput =
      some ⟨.decs, openingPayload.bytes⟩)
    (matrixGood : ¬ currentMatrixBad
      (SmzaQ38McaSourceBinding.oracleData
        (SmzaRp05TracePrefixes.rootOracle ns
          (extract (globalOnlineNext ns) filteredRecords fuel .root pcs.post.root)))
      (SmzaQ38McaSourceBinding.oracleMasks
        (SmzaRp05TracePrefixes.rootOracle ns
          (extract (globalOnlineNext ns) filteredRecords fuel .root pcs.post.root)))
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients (gammaRows pcs.post)))
    (classifierBad : currentSourceBad406
      (currentSourcePrefix406
        (SmzaRp05TracePrefixes.rootOracle ns
          (extract (globalOnlineNext ns) filteredRecords fuel .root pcs.post.root))
        fpp (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients (gammaRows pcs.post))
        (fun opening => (List.ofFn fun j : Fin 6 =>
          V8Smz9PiopReconstruction.points execution.opening j).getD opening.val 0)
        (queryCoefficients openingPayload) matrixGood)
      query) :
    ∃ trace : Trace, trace = extract (globalOnlineNext ns) filteredRecords
      28 .decs pcs.openingDigest ∧
      ∃ messages : CausalPayloads ns trace,
        messages.fpp.bytes = fpp.bytes ∧
        queryCoefficients messages.decs = queryCoefficients openingPayload ∧
        ∃ causalMatrixGood : ¬ currentMatrixBad
          (SmzaQ38McaSourceBinding.oracleData (SmzaRp05AcceptedRoleLabels.causalOracle ns trace))
          (SmzaQ38McaSourceBinding.oracleMasks (SmzaRp05AcceptedRoleLabels.causalOracle ns trace))
          (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients (gammaRows pcs.post)),
          currentSourceBad406
            (currentSourcePrefix406
              (SmzaRp05AcceptedRoleLabels.causalOracle ns trace) messages.fpp
              (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients (gammaRows pcs.post))
              (V8Smz9AdaptiveFiniteAccounting.baseOpeningPoints execution.opening.1)
              (queryCoefficients messages.decs) causalMatrixGood) query := by
  classical
  -- The causal record theorem derives actual verifier/PCS retention from
  -- acceptance and the nonchallenge-only raw-log inclusion.
  obtain ⟨openingFull, finalFull, hashFull⟩ :=
    accepted_execution_causal_record_memberships ns dsl statement pending nonce wire oracle
      transcript execution pcs fullRecords verifierAccepted transcriptSuccess nonchallengeRetained
  obtain ⟨decsRows, _rowsBuilt, decsParsed, decsNormalized, decsNext⟩ :=
    current_decs_opening_edge406 ns wire.hPiop pcs.heads
      execution.middle.pcs.rcombiTails pcs.openingInput pcs.openingBuilt
  let decsPayload : Payload := ⟨.decs,
    (SmzaRp05ExecutableChallengeStage.digestWords wire.hPiop ++ decsRows).flatMap (encodeLE 8)⟩
  have decsFiltered := retained_nonleaf_survives_current_filter ns statement fullRecords
    filteredRecords pcs.openingInput pcs.openingDigest decsPayload decsNormalized
    (by change V8SmzaOracleParser.Kind.decs ≠ V8SmzaOracleParser.Kind.leaf; decide)
    openingFull filterEq
  have piopNormalized := current_final_normalized_payload ns transcript
  let piopPayload : Payload := ⟨.piop, SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩
  have piopFiltered := retained_nonleaf_survives_current_filter ns statement fullRecords
    filteredRecords (SmzaRp05ExecutableFinalVerifier.finalInput transcript) wire.hPiop
    piopPayload piopNormalized
    (by change V8SmzaOracleParser.Kind.piop ≠ V8SmzaOracleParser.Kind.leaf; decide)
    finalFull filterEq
  obtain ⟨selectedInput, fppBytes, selectedAsk, _frame, fppNormalized, fppNext, _suffix⟩ :=
    successful_response_program_has_current_fpp_edge ns pcs.post.root execution.decs
      (pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      (gammaRows pcs.post)
      (pcs.decsPoints.map fun point => SmzaRp05ExecutableRestore.toWord point)
      (statementBindingWords statement)
      (SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement)
      pcs.hashProgram pcs.responseBuilt
  have fppHashFresh := successful_response_hash_records_nonleaf ns pcs.post.root execution.decs
      (pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      (gammaRows pcs.post)
      (pcs.decsPoints.map fun point => SmzaRp05ExecutableRestore.toWord point)
      (statementBindingWords statement)
      (SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement)
      pcs.hashProgram pcs.responseBuilt oracle
  have hashFiltered : ∀ call, call ∈ (pcs.hashProgram.record oracle).2 → call ∈ filteredRecords := by
    intro call callMember
    have fullMember := hashFull call callMember
    have nonleaf := fppHashFresh call callMember
    have queryNone : parseStageQuery call.1 = none := by
      cases parsed : parseStageQuery call.1 with
      | none => rfl
      | some challenge =>
          have impossible := SmzaRp05ChallengeRecordErasure.parse_stage_query_global_payload_none
            ns call.1 challenge parsed
          -- Every hash-program call is the unique generated response input.
          have normalizedCall : globalNormalizedPayload ns call.1 = some ⟨.fpp, fppBytes⟩ := by
            rw [selectedAsk] at callMember
            have callEq : call = (selectedInput, oracle selectedInput) := by
              simpa only [ask, Program.record, List.mem_singleton] using callMember
            simpa only [callEq] using fppNormalized
          rw [normalizedCall] at impossible
          cases impossible
    have erased : call ∈ eraseChallengeRecords fullRecords := by
      apply Finset.mem_filter.mpr
      exact ⟨fullMember, by simp only [queryNone]; rfl⟩
    rw [filterEq]
    apply Finset.mem_filter.mpr
    exact ⟨erased, Or.inl nonleaf⟩
  have causal := current_causal_payloads_and_targets_of_stages ns dsl statement pending
    nonce wire oracle transcript execution pcs filteredRecords collisionFree
    decsFiltered piopFiltered hashFiltered
  obtain ⟨trace, traceEq, messages, _fppTarget, _piopTarget, _decsTarget⟩ := causal
  have selectedRecord : (selectedInput, execution.hashFpp) ∈
      (pcs.hashProgram.record oracle).2 := by
    rw [selectedAsk]
    have value : oracle selectedInput = execution.hashFpp := by
      have executed := pcs.hashExecuted
      rw [selectedAsk] at executed
      simpa [ask, Program.eval] using executed
    simp [ask, Program.record, value]
  have callEq : (input, execution.hashFpp) = (selectedInput, oracle selectedInput) := by
    rw [selectedAsk] at inputRecord
    simpa [ask, Program.record] using inputRecord
  have inputEq : input = selectedInput := congrArg Prod.fst callEq
  have normalizedSelected : globalNormalizedPayload ns selectedInput =
      some (⟨.fpp, fpp.bytes⟩ : Payload) := by
    rw [← inputEq]
    exact inputNormalized
  have classifierFppPayloadBytes : fpp.bytes = fppBytes := by
    have same : some (⟨.fpp, fpp.bytes⟩ : Payload) =
        some (⟨.fpp, fppBytes⟩ : Payload) := normalizedSelected.symm.trans fppNormalized
    exact congrArg (fun payload : Payload => payload.bytes) (Option.some.inj same)
  have selectedFppRecorded := hashFiltered _ selectedRecord
  have piopNext := current_final_piop_edge ns transcript
  have transcriptHash : transcript.hashFpp = execution.hashFpp := by
    have projected := congrArg
      SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript.hashFpp execution.reconstructed
    simpa [SmzaRp05ExecutableReconstruction.reconstruct] using projected.symm
  have piopNext' : globalOnlineNext ns .piop
      (SmzaRp05ExecutableFinalVerifier.finalInput transcript) =
        some [(.fpp, execution.hashFpp)] := by
    simpa [transcriptHash] using piopNext
  have decsChain := global_recorded_decs_chain ns filteredRecords collisionFree
    pcs.openingDigest wire.hPiop execution.hashFpp pcs.post.root pcs.openingInput
    (SmzaRp05ExecutableFinalVerifier.finalInput transcript) selectedInput
    decsFiltered piopFiltered selectedFppRecorded decsNext piopNext' fppNext 28 (by decide)
  have fppTraceEq : causalTrace trace .piopMatrix =
      extract (globalOnlineNext ns) filteredRecords 28 .fpp execution.hashFpp := by
    rw [traceEq, decsChain]
    have fppSingle := global_recorded_single_child_trace ns filteredRecords collisionFree
      .fpp .root execution.hashFpp pcs.post.root selectedInput selectedFppRecorded
      fppNext 28 (by decide)
    change V8Smz9CoherentMerkleGeometry.ExtractionTrace.record selectedInput
      [extract (globalOnlineNext ns) filteredRecords 28 .root pcs.post.root] = _
    exact fppSingle.symm
  have fppTraceEqExtract :
      causalTrace (extract (globalOnlineNext ns) filteredRecords 28 .decs
        pcs.openingDigest) .piopMatrix =
          extract (globalOnlineNext ns) filteredRecords 28 .fpp execution.hashFpp := by
    have samePath := congrArg (fun tr : Trace => causalTrace tr .piopMatrix) traceEq
    exact samePath.symm.trans fppTraceEq
  have fppValid : (V8SmzaOnlineParser.payloadNext .fpp
      (⟨.fpp, fppBytes⟩ : Payload)).isSome := by
    have nextSome : (globalOnlineNext ns .fpp selectedInput).isSome := by
      rw [fppNext]
      simp
    change (do
      let parsed ← globalNormalizedPayload ns selectedInput
      V8SmzaOnlineParser.payloadNext .fpp parsed).isSome = true at nextSome
    rw [fppNormalized] at nextSome
    change (V8SmzaOnlineParser.payloadNext .fpp
      (⟨.fpp, fppBytes⟩ : Payload)).isSome = true at nextSome
    exact nextSome
  have fppRead := global_payload_of_recorded_input ns filteredRecords collisionFree
    .fpp execution.hashFpp selectedInput (⟨.fpp, fppBytes⟩ : Payload)
    selectedFppRecorded fppNormalized fppValid 28 (by decide)
  have messageFppRead := messages.fppRead
  have messageFppReadAtExtract :
      SmzaRp05TracePrefixes.payload ns .fpp
        (causalTrace (extract (globalOnlineNext ns) filteredRecords 28 .decs
          pcs.openingDigest) .piopMatrix) = some messages.fpp := by
    have transported := congrArg
      (fun tr : Trace => SmzaRp05TracePrefixes.payload ns .fpp
        (causalTrace tr .piopMatrix)) traceEq
    exact transported.symm.trans messageFppRead
  have sameFpp : some messages.fpp = some (⟨.fpp, fppBytes⟩ : Payload) :=
    messageFppReadAtExtract.symm.trans
      ((congrArg (SmzaRp05TracePrefixes.payload ns .fpp) fppTraceEqExtract).trans fppRead)
  have fppBytesCausal : messages.fpp.bytes = fpp.bytes := by
    calc
      messages.fpp.bytes = fppBytes :=
        congrArg (fun payload : Payload => payload.bytes) (Option.some.inj sameFpp)
      _ = fpp.bytes := classifierFppPayloadBytes.symm
  have openingBytesEq : openingPayload.bytes = decsPayload.bytes := by
    have parsedEq := Option.some.inj (openingParsed.symm.trans decsParsed)
    exact congrArg Prod.snd parsedEq
  have messagePayloadEq : messages.decs = decsPayload := by
    have actualPayloadEq : globalNormalizedPayload ns pcs.openingInput = some decsPayload :=
      decsNormalized
    have decsValid : (V8SmzaOnlineParser.payloadNext .decs decsPayload).isSome := by
      have nextSome : (globalOnlineNext ns .decs pcs.openingInput).isSome := by
        rw [decsNext]
        simp
      change (do
        let parsed ← globalNormalizedPayload ns pcs.openingInput
        V8SmzaOnlineParser.payloadNext .decs parsed).isSome = true at nextSome
      rw [actualPayloadEq] at nextSome
      change (V8SmzaOnlineParser.payloadNext .decs decsPayload).isSome = true at nextSome
      exact nextSome
    have read := global_payload_of_recorded_input ns filteredRecords collisionFree
      .decs pcs.openingDigest pcs.openingInput decsPayload decsFiltered actualPayloadEq
      decsValid 28 (by decide)
    have messageRead := messages.decsRead
    have transported := congrArg
      (fun tr : Trace => SmzaRp05TracePrefixes.payload ns .decs
        (causalTrace tr .decsSample)) traceEq
    have messageReadAtExtract :
        SmzaRp05TracePrefixes.payload ns .decs
          (causalTrace (extract (globalOnlineNext ns) filteredRecords 28 .decs
            pcs.openingDigest) .decsSample) = some messages.decs :=
      transported.symm.trans messageRead
    have same : some messages.decs = some decsPayload := by
      simpa only [causalTrace] using messageReadAtExtract.symm.trans read
    exact Option.some.inj same
  have coeffEq : queryCoefficients messages.decs = queryCoefficients openingPayload := by
    have bytesEq : messages.decs.bytes = openingPayload.bytes := by
      calc
        messages.decs.bytes = decsPayload.bytes :=
          congrArg (fun payload : Payload => payload.bytes) messagePayloadEq
        _ = openingPayload.bytes := openingBytesEq.symm
    calc
      queryCoefficients messages.decs =
          queryCoefficients (⟨.decs, messages.decs.bytes⟩ : Payload) := by
        cases messages.decs
        rfl
      _ = queryCoefficients (⟨.decs, openingPayload.bytes⟩ : Payload) :=
        congrArg (fun bytes => queryCoefficients (⟨.decs, bytes⟩ : Payload)) bytesEq
      _ = queryCoefficients openingPayload := by
        cases openingPayload
        rfl
  have causalRootEq : causalTrace trace .decsMatrix =
      extract (globalOnlineNext ns) filteredRecords fuel .root pcs.post.root := by
    have traceRoot : causalTrace trace .decsMatrix =
        extract (globalOnlineNext ns) filteredRecords 28 .root pcs.post.root := by
      rw [traceEq, decsChain]
      rfl
    calc
      causalTrace trace .decsMatrix =
          extract (globalOnlineNext ns) filteredRecords 28 .root pcs.post.root := traceRoot
      _ = extract (globalOnlineNext ns) filteredRecords fuel .root pcs.post.root :=
        global_sufficient_fuel_same_trace ns filteredRecords 28 fuel .root pcs.post.root
          (by norm_num [SmzaRawTraceDepth.stageDepth])
          (by norm_num [SmzaRawTraceDepth.stageDepth]; omega)
  have rootEq : SmzaRp05AcceptedRoleLabels.causalOracle ns trace =
      SmzaRp05TracePrefixes.rootOracle ns
        (extract (globalOnlineNext ns) filteredRecords fuel .root pcs.post.root) := by
    exact congrArg (SmzaRp05TracePrefixes.rootOracle ns) causalRootEq
  have matrixGoodCausal : ¬ currentMatrixBad
      (SmzaQ38McaSourceBinding.oracleData (SmzaRp05AcceptedRoleLabels.causalOracle ns trace))
      (SmzaQ38McaSourceBinding.oracleMasks (SmzaRp05AcceptedRoleLabels.causalOracle ns trace))
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients (gammaRows pcs.post)) := by
    rw [rootEq]
    exact matrixGood
  have pointEq : (fun opening => (List.ofFn fun j : Fin 6 =>
        V8Smz9PiopReconstruction.points execution.opening j).getD opening.val 0) =
      V8Smz9AdaptiveFiniteAccounting.baseOpeningPoints execution.opening.1 := by
    funext opening
    have bound : opening.val < 6 := opening.isLt
    change (List.ofFn (V8Smz9PiopReconstruction.points execution.opening)).getD
      opening.val 0 = V8Smz9PiopReconstruction.points execution.opening opening
    simp only [List.getD_eq_getElem?_getD, List.getElem?_ofFn,
      bound, dif_pos, Option.getD_some]
    exact congrArg (V8Smz9PiopReconstruction.points execution.opening)
      (Fin.ext rfl)
  have sourceBadCausal : currentSourceBad406
      (currentSourcePrefix406 (SmzaRp05AcceptedRoleLabels.causalOracle ns trace)
        messages.fpp
        (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients (gammaRows pcs.post))
        (V8Smz9AdaptiveFiniteAccounting.baseOpeningPoints execution.opening.1)
          (queryCoefficients messages.decs) matrixGoodCausal) query := by
    have responseEq :
      SmzaRp05CurrentTracePrefixes406.currentResponseRule406 messages.fpp =
          SmzaRp05CurrentTracePrefixes406.currentResponseRule406 fpp := by
      have leftCanonical :
          SmzaRp05CurrentTracePrefixes406.currentResponseRule406 messages.fpp =
            SmzaRp05CurrentTracePrefixes406.currentResponseRule406
              (⟨.fpp, messages.fpp.bytes⟩ : Payload) := by
        cases messages.fpp
        rfl
      have rightCanonical :
          SmzaRp05CurrentTracePrefixes406.currentResponseRule406 fpp =
            SmzaRp05CurrentTracePrefixes406.currentResponseRule406
              (⟨.fpp, fpp.bytes⟩ : Payload) := by
        cases fpp
        rfl
      exact leftCanonical.trans
        ((congrArg (fun bytes =>
          SmzaRp05CurrentTracePrefixes406.currentResponseRule406
            (⟨.fpp, bytes⟩ : Payload)) fppBytesCausal).trans rightCanonical.symm)
    have prefixEq :
        currentSourcePrefix406 (SmzaRp05AcceptedRoleLabels.causalOracle ns trace)
        messages.fpp
        (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients (gammaRows pcs.post))
        (V8Smz9AdaptiveFiniteAccounting.baseOpeningPoints execution.opening.1)
          (queryCoefficients messages.decs) matrixGoodCausal =
          currentSourcePrefix406
            (SmzaRp05TracePrefixes.rootOracle ns
              (extract (globalOnlineNext ns) filteredRecords fuel .root pcs.post.root))
            fpp (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients (gammaRows pcs.post))
            (fun opening => (List.ofFn fun j : Fin 6 =>
              V8Smz9PiopReconstruction.points execution.opening j).getD opening.val 0)
            (queryCoefficients openingPayload) matrixGood := by
      exact current_source_prefix406_congr
        (SmzaRp05AcceptedRoleLabels.causalOracle ns trace)
        (SmzaRp05TracePrefixes.rootOracle ns
          (extract (globalOnlineNext ns) filteredRecords fuel .root pcs.post.root))
        messages.fpp fpp
        (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients (gammaRows pcs.post))
        (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients (gammaRows pcs.post))
        (V8Smz9AdaptiveFiniteAccounting.baseOpeningPoints execution.opening.1)
        (fun opening => (List.ofFn fun j : Fin 6 =>
          V8Smz9PiopReconstruction.points execution.opening j).getD opening.val 0)
        (queryCoefficients messages.decs) (queryCoefficients openingPayload)
        matrixGoodCausal matrixGood rootEq fppBytesCausal rfl pointEq.symm coeffEq
    rw [prefixEq]
    exact classifierBad
  exact ⟨trace, traceEq, messages, fppBytesCausal, coeffEq,
    ⟨matrixGoodCausal, sourceBadCausal⟩⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFilteredCausalSourceBad
