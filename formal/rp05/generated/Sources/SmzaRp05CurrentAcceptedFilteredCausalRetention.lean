import SmzaRp05CurrentAcceptedCausalPayloads
import SmzaRp05CurrentCausalNonchallengeRetention
import SmzaRp05CurrentFppRecordFreshness
import SmzaRp05CurrentAcceptedFilteredRoleTraces
import SmzaRp05AcceptedRoleLabels
import SmzaRp05CurrentTracePrefixes406
import SmzaRp05CurrentAcceptedQuerySupport

/-! # Same-execution filtered causal record retention

Expose the actual opening, final and FPP-hash calls that survive the current
statement filter. This reuses the already checked causal-source retention
construction and supplies the executed earlier-advice consumer directly. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFilteredCausalRetention

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

theorem accepted_execution_supplies_filtered_causal_records
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
    (verifierAccepted : (verifierProgram ns dsl statement pending nonce wire).eval oracle = some ())
    (transcriptSuccess : (transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire).eval oracle = some transcript)
    (nonchallengeRetained : ∀ call,
      call ∈ ((verifierProgram ns dsl statement pending nonce wire).record oracle).2 →
      parseStageQuery call.1 = none → call ∈ fullRecords)
    : (pcs.openingInput, pcs.openingDigest) ∈ filteredRecords ∧
      (SmzaRp05ExecutableFinalVerifier.finalInput transcript, wire.hPiop) ∈ filteredRecords ∧
      (∀ call, call ∈ (pcs.hashProgram.record oracle).2 → call ∈ filteredRecords) := by
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
  exact ⟨decsFiltered, piopFiltered, hashFiltered⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFilteredCausalRetention

