import SmzaRp05CurrentAcceptedXViewRoleCoverage
import SmzaRp05CurrentAcceptedCausalPayloadIdentity
import SmzaRp05AcceptedRoleLabels
import SmzaRp05CurrentPiopFrameReadback
import SmzaRp05CurrentPiopRoleEvents

/-! # Same-stage classifier to causal PIOP failure bridge

The accepted filtered classifier decodes against the root extracted from the
statement-filtered records.  Dynamic role events consume the causal oracle
assembled from the same execution's DECS trace.  This adapter transports the
classifier's exact PIOP source recovery across that recorded root-trace
identity; it does not posit a second source, message, or failure witness.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopClassifierCoverage

open SmzaRp05CurrentAcceptedXViewRoleCoverage (noWitnessRoleFailure)
open SmzaRp05AcceptedRoleLabels
  (CausalPayloads causalOracle causalTrace global_payload_of_recorded_input)
open SmzaRp05CurrentAcceptedCausalPayloadIdentity
  (causal_payloads_unique retained_hash_call_has_causal_fpp_payload)
open SmzaRp05CurrentPiopFrameReadback (current_final_normalized_payload current_final_piop_edge)
open SmzaRp05TracePrefixes (rootOracle)
open SmzaRp05CurrentTracePrefixes406 (currentSourceDecoder406)
open SmzaRp05CurrentTracePrefixes406 (currentResponseRule406)
open SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients)
open SmzaRp05PcsHashFppMiddle (gammaRows)
open SmzaRp05PcsToFinalProgram (sameProofRows)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentAcceptedCausalPayloads (Records)
open SmzaRp05RelationRefinement (RelationDsl relationModel)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp05FilteredDecoderInstability (globalNormalizedPayload)
open SmzaRp05TracePrefixes (Trace Payload payload piopResponse)
open SmzaRp04TracePrefixes (sourceResponse sourceCoefficients)
open SmzaRp04StatementRecordFilter (oneStatementFilter)
open V8Smz9CoherentMerkleGeometry (extract)
open V8SmzaOracleParser (RawInput RawDigest)
open SmzaRp05CurrentPiopRoleEvents (PiopRole)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 30000
set_option maxHeartbeats 1600000

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local notation "Payload" => SmzaRp05TracePrefixes.Payload

attribute [local irreducible]
  HegemonCrypto.SmallWood.SmzaRp04ChronologicalAlgebra.piopMatrixBadEvent
  HegemonCrypto.SmallWood.SmzaRp04ChronologicalAlgebra.piopOpeningBadEvent

/-- A PIOP-arm classifier failure is already an exact same-execution source
and local bad-event witness.  Once the filtered root extraction is identified
with the causal DECS trace, its recovered source is the source consumed by the
causal PIOP event constructor.  `messages` and `rootTraceEq` are the literal
same-trace readback objects; callers derive them from the accepted execution
and its filtered-role trace theorem. -/
theorem classified_piop_failure_transports_to_causal_trace
    (role : PiopRole)
    (ns : Namespace) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView)
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns SmzaRp05GeneratedCertificates.currentDsl
      statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (sameProofRows execution.middle.pcs execution.piop) execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending)
    [Fintype RawDigest]
    (records : Records) (fuel : Nat) (input : RawInput)
    (query : SmzaRp05CurrentMaxAgreementRecovery.Query)
    (trace : Trace) (messages : CausalPayloads ns trace)
    (collisionFree : SmzaRecordedTracePath.RecordsCollisionFree
      (oneStatementFilter (globalLeafStatement ns) statement.toBytes records))
    (inputRecorded : (input, execution.hashFpp) ∈ (pcs.hashProgram.record oracle).2)
    (openingRecorded : (pcs.openingInput, pcs.openingDigest) ∈
      (oneStatementFilter (globalLeafStatement ns) statement.toBytes records))
    (finalRecorded : (SmzaRp05ExecutableFinalVerifier.finalInput transcript, wire.hPiop) ∈
      (oneStatementFilter (globalLeafStatement ns) statement.toBytes records))
    (hashRecordRetained : ∀ call,
      call ∈ (pcs.hashProgram.record oracle).2 →
        call ∈ oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
    (traceEq : trace = extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
        28 .decs pcs.openingDigest)
    (rootTraceEq : extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
        fuel .root pcs.post.root = causalTrace trace .decsMatrix)
    (piopTraceEq : extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
        28 .piop wire.hPiop = causalTrace trace .piopOpening)
      (failure : noWitnessRoleFailure role.toRole ns statement pending nonce wire oracle
        transcript execution pcs records fuel input query) :
    match role with
  | .matrix =>
        ∃ source : V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140,
          currentSourceDecoder406 (causalOracle ns trace) messages.fpp
            (sampledCoefficients (gammaRows pcs.post)) = some source ∧
          ((¬ HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
              ((relationModel SmzaRp05GeneratedCertificates.currentDsl
                SmzaRp05GeneratedCertificates.certificates).recoveredCandidate
                statement source.data).system) ∧
            execution.matrix ∈ SmzaRp04ChronologicalAlgebra.piopMatrixBadEvent
              ((relationModel SmzaRp05GeneratedCertificates.currentDsl
                SmzaRp05GeneratedCertificates.certificates).recoveredCandidate
                statement source.data))
  | .opening =>
        ∃ source : V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140,
          currentSourceDecoder406 (causalOracle ns trace) messages.fpp
            (sampledCoefficients (gammaRows pcs.post)) = some source ∧
          ((¬ HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
              ((relationModel SmzaRp05GeneratedCertificates.currentDsl
                SmzaRp05GeneratedCertificates.certificates).recoveredCandidate
                statement source.data).system) ∧
            execution.opening ∈ SmzaRp04ChronologicalAlgebra.piopOpeningBadEvent
              ((relationModel SmzaRp05GeneratedCertificates.currentDsl
                SmzaRp05GeneratedCertificates.certificates).recoveredCandidate
                statement source.data) execution.matrix
      (SmzaRp05TracePrefixes.piopResponse messages.piop)) := by
  classical
  subst trace
  let trace := extract (globalOnlineNext ns)
    (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
    28 .decs pcs.openingDigest
  cases role with
  | matrix =>
      dsimp only [noWitnessRoleFailure] at failure ⊢
      rcases failure with ⟨_matrixGood, fpp, openingPayload, _parsedInput,
        _normalizedInput, _inputSuffix, _parsedOpening, _normalizedOpening,
        _claimsRead, source, recovered, _rows, notFull, matrixBad⟩
      have causalFpp := retained_hash_call_has_causal_fpp_payload ns
        SmzaRp05GeneratedCertificates.currentDsl statement pending nonce wire oracle
        transcript execution pcs
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
        collisionFree openingRecorded finalRecorded
        hashRecordRetained input inputRecorded ⟨.fpp, fpp.bytes⟩ _normalizedInput
      obtain ⟨messages', messagesFpp⟩ := causalFpp
      have messagesEq := causal_payloads_unique messages messages'
      have fppBytes : messages.fpp.bytes = fpp.bytes := by
        have normalizedBytes := congrArg (fun p : Payload => p.bytes) messagesFpp
        have uniqueBytes := congrArg
          (fun package : CausalPayloads ns trace => package.fpp.bytes) messagesEq
        simpa only [normalizedBytes] using uniqueBytes
      have responseRuleEq : currentResponseRule406 messages.fpp =
          currentResponseRule406 fpp := by
        exact congrArg (fun bytes => currentResponseRule406
          (⟨.fpp, bytes⟩ : Payload)) fppBytes
      have oracleEq :
          rootOracle ns (extract (globalOnlineNext ns)
            (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
            fuel .root pcs.post.root) = causalOracle ns trace :=
        congrArg (rootOracle ns) rootTraceEq
      refine ⟨source, ?_, ⟨notFull, matrixBad⟩⟩
      have oracleDecoderEq := congrArg
        (fun sourceOracle => currentSourceDecoder406 sourceOracle fpp
          (sampledCoefficients (gammaRows pcs.post))) oracleEq
      have causalAtFpp := oracleDecoderEq.symm.trans recovered
      dsimp only [currentSourceDecoder406] at causalAtFpp ⊢
      rw [← responseRuleEq] at causalAtFpp
      exact causalAtFpp
  | opening =>
      dsimp only [noWitnessRoleFailure] at failure ⊢
      rcases failure with ⟨_matrixGood, fpp, openingPayload, _parsedInput,
        _normalizedInput, _inputSuffix, _parsedOpening, _normalizedOpening,
        _claimsRead, source, recovered, _rows, notFull, openingBad⟩
      have causalFpp := retained_hash_call_has_causal_fpp_payload ns
        SmzaRp05GeneratedCertificates.currentDsl statement pending nonce wire oracle
        transcript execution pcs
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
        collisionFree openingRecorded finalRecorded
        hashRecordRetained input inputRecorded ⟨.fpp, fpp.bytes⟩ _normalizedInput
      obtain ⟨messages', messagesFpp⟩ := causalFpp
      have messagesEq := causal_payloads_unique messages messages'
      have fppBytes : messages.fpp.bytes = fpp.bytes := by
        have normalizedBytes := congrArg (fun p : Payload => p.bytes) messagesFpp
        have uniqueBytes := congrArg
          (fun package : CausalPayloads ns trace => package.fpp.bytes) messagesEq
        simpa only [normalizedBytes] using uniqueBytes
      have responseRuleEq : currentResponseRule406 messages.fpp =
          currentResponseRule406 fpp := by
        exact congrArg (fun bytes => currentResponseRule406
          (⟨.fpp, bytes⟩ : Payload)) fppBytes
      let finalPayload : Payload := ⟨.piop,
        SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩
      have piopNormalized := current_final_normalized_payload ns transcript
      have piopValid :
          (V8SmzaOnlineParser.payloadNext .piop finalPayload).isSome := by
        have next := current_final_piop_edge ns transcript
        have parsedNext : V8SmzaOnlineParser.payloadNext .piop finalPayload =
            some [(.fpp, transcript.hashFpp)] := by
          simpa [SmzaRp05FilteredDecoderInstability.globalOnlineNext,
            piopNormalized, finalPayload] using next
        simp [parsedNext]
      have extractedPiop := global_payload_of_recorded_input ns
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
        collisionFree .piop wire.hPiop
        (SmzaRp05ExecutableFinalVerifier.finalInput transcript) finalPayload
        finalRecorded piopNormalized piopValid 28 (by decide)
      have causalPiop : payload ns .piop (causalTrace trace .piopOpening) =
          some messages.piop := by
        simpa only [causalTrace] using messages.piopRead
      have causalPiopOnExtracted : payload ns .piop
          (extract (globalOnlineNext ns)
            (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
            28 .piop wire.hPiop) = some messages.piop :=
        piopTraceEq ▸ causalPiop
      have piopEq : messages.piop = finalPayload :=
        Option.some.inj (causalPiopOnExtracted.symm.trans extractedPiop)
      have oracleEq :
          rootOracle ns (extract (globalOnlineNext ns)
            (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
            fuel .root pcs.post.root) = causalOracle ns trace :=
        congrArg (rootOracle ns) rootTraceEq
      have openingBad' :
          execution.opening ∈ SmzaRp04ChronologicalAlgebra.piopOpeningBadEvent
            ((relationModel SmzaRp05GeneratedCertificates.currentDsl
              SmzaRp05GeneratedCertificates.certificates).recoveredCandidate
              statement source.data) execution.matrix (piopResponse messages.piop) := by
        simpa only [piopEq] using openingBad
      refine ⟨source, ?_, ⟨notFull, openingBad'⟩⟩
      have oracleDecoderEq := congrArg
        (fun sourceOracle => currentSourceDecoder406 sourceOracle fpp
          (sampledCoefficients (gammaRows pcs.post))) oracleEq
      have causalAtFpp := oracleDecoderEq.symm.trans recovered
      dsimp only [currentSourceDecoder406] at causalAtFpp ⊢
      rw [← responseRuleEq] at causalAtFpp
      exact causalAtFpp

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopClassifierCoverage
