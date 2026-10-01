import SmzaRp05CurrentAcceptedCausalPayloads
import SmzaRp05CurrentExecutedEarlierAdvice
import SmzaRp05ChallengeRecordErasure
import SmzaRp05CurrentPrequeryChronology
import SmzaRp05PhysicalPcsRecordRetention

/-! # Actual causal-query records from nonchallenge verifier retention

The three records consumed by the causal payload and earlier-advice readbacks
are recovered from the same successful verifier execution. The only record
retention premise is for verifier-log calls whose inputs do not parse as
challenge queries; DECS, final PIOP, and response FPP framing proves precisely
that condition for the selected calls.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentCausalNonchallengeRetention

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableMerkleVerifier (Oracle Program)
open SmzaRp05ExecutablePcsClosure (ExecutionStages transcriptProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureStatement (statementBindingWords verifierProgram)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentAcceptedCausalPayloads (Records)
open SmzaRp05CurrentPrequeryChronology (pcs_q38_record_split)
open SmzaRp05PhysicalPcsRecordRetention (execution_pcs_records_retained_in_verifier)
open SmzaRp05CurrentFppFrameReadback (successful_response_program_has_current_fpp_edge)
open SmzaRp05CurrentDecsFrameReadback (current_decs_opening_edge406)
open SmzaRp05CurrentPiopFrameReadback (current_final_normalized_payload)
open SmzaRp05FilteredDecoderInstability (globalNormalizedPayload)
open SmzaChallengeStageTargets (parseStageQuery)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

private theorem parse_none_of_normalized_payload
    (ns : Namespace) (input : RawInput) (payload : SmzaRp05TracePrefixes.Payload)
    (normalized : globalNormalizedPayload ns input = some payload) :
    parseStageQuery input = none := by
  cases parsed : parseStageQuery input with
  | none => rfl
  | some query =>
      have payloadNone :=
        SmzaRp05ChallengeRecordErasure.parse_stage_query_global_payload_none
          ns input query parsed
      rw [normalized] at payloadNone
      cases payloadNone

/-- Retention of the three actual causal inputs follows from parse-none-only
verifier-log retention. Every witness is tied to this `ExecutionStages` and
`PcsStages` pair; no opening/final/hash record membership is supplied by the
caller. -/
theorem accepted_execution_causal_record_memberships
    (ns : Namespace) (dsl : RelationDsl) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView)
    (oracle : Oracle) (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending)
    [Fintype RawDigest]
    (records : Records)
    (verifierAccepted : (verifierProgram ns dsl statement pending nonce wire).eval oracle = some ())
    (transcriptSuccess : (transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire).eval oracle = some transcript)
    (nonchallengeRetained : ∀ call,
      call ∈ ((verifierProgram ns dsl statement pending nonce wire).record oracle).2 →
      parseStageQuery call.1 = none → call ∈ records) :
    (pcs.openingInput, pcs.openingDigest) ∈ records ∧
      (SmzaRp05ExecutableFinalVerifier.finalInput transcript, wire.hPiop) ∈ records ∧
      (∀ call, call ∈ (pcs.hashProgram.record oracle).2 → call ∈ records) := by
  have openingInPcs : (pcs.openingInput, pcs.openingDigest) ∈
      ((SmzaRp05ExecutablePcsClosure.pcsProgram ns execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt statement.toBytes (statementBindingWords statement)
        wire.tapes wire.paths).record oracle).2 := by
    rw [pcs_q38_record_split ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending pcs]
    simp
  have pcsRetained := execution_pcs_records_retained_in_verifier ns dsl statement
    pending nonce wire oracle transcript execution transcriptSuccess
  have openingInVerifier := pcsRetained _ openingInPcs
  obtain ⟨decsRows, _rowsFormed, _decsParsed, decsNormalized, _decsNext⟩ :=
    current_decs_opening_edge406 ns wire.hPiop pcs.heads
      execution.middle.pcs.rcombiTails pcs.openingInput pcs.openingBuilt
  have openingNonchallenge := parse_none_of_normalized_payload ns pcs.openingInput
    ⟨.decs, (SmzaRp05ExecutableChallengeStage.digestWords wire.hPiop ++ decsRows).flatMap
      (encodeLE 8)⟩ decsNormalized
  have openingRecorded := nonchallengeRetained (pcs.openingInput, pcs.openingDigest)
    openingInVerifier openingNonchallenge
  obtain ⟨acceptedTranscript, acceptedTranscriptSuccess, _clean, _hashEq,
      finalMember⟩ :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl
      statement pending statement.toBytes (statementBindingWords statement)
      nonce wire oracle verifierAccepted
  have transcriptEq : acceptedTranscript = transcript :=
    Option.some.inj (acceptedTranscriptSuccess.symm.trans transcriptSuccess)
  subst acceptedTranscript
  have finalNonchallenge := parse_none_of_normalized_payload ns
    (SmzaRp05ExecutableFinalVerifier.finalInput transcript)
    ⟨.piop, SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩
    (current_final_normalized_payload ns transcript)
  have finalRecorded := nonchallengeRetained
    (SmzaRp05ExecutableFinalVerifier.finalInput transcript, wire.hPiop)
    finalMember finalNonchallenge
  obtain ⟨fppInput, fppBytes, selectedAsk, _fppFramed, fppNormalized,
      _fppEdge, _fppSuffix⟩ :=
    successful_response_program_has_current_fpp_edge ns pcs.post.root execution.decs
      (pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)
      (pcs.decsPoints.map SmzaRp05ExecutableRestore.toWord)
      (statementBindingWords statement)
      (SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement)
      pcs.hashProgram pcs.responseBuilt
  have fppNonchallenge := parse_none_of_normalized_payload ns fppInput
    ⟨.fpp, fppBytes⟩ fppNormalized
  have fppValue : oracle fppInput = execution.hashFpp := by
    have executed := pcs.hashExecuted
    rw [selectedAsk] at executed
    simpa [SmzaRp05ExecutableMerkleVerifier.ask, Program.eval] using executed
  have hashLogEq : (pcs.hashProgram.record oracle).2 = [(fppInput, execution.hashFpp)] := by
    rw [selectedAsk]
    simp [SmzaRp05ExecutableMerkleVerifier.ask, Program.record, fppValue]
  have hashToVerifier :=
    SmzaRp05PhysicalHashFppRecordRetention.execution_hash_fpp_records_retained_in_verifier
      ns dsl statement pending nonce wire oracle transcript execution pcs transcriptSuccess
  have hashRecordRetained : ∀ call,
      call ∈ (pcs.hashProgram.record oracle).2 → call ∈ records := by
    intro call member
    have callEq : call = (fppInput, execution.hashFpp) := by
      rw [hashLogEq] at member
      exact List.mem_singleton.mp member
    have inVerifier := hashToVerifier call member
    rw [callEq] at inVerifier ⊢
    exact nonchallengeRetained (fppInput, execution.hashFpp) inVerifier fppNonchallenge
  exact ⟨openingRecorded, finalRecorded, hashRecordRetained⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentCausalNonchallengeRetention
