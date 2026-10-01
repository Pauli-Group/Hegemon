import SmzaRp05CurrentAcceptedCausalPayloads

/-! # Same-stage FPP payload identity

The retained FPP query in an accepted classification is the same singleton
query built by the current response program.  Its normalized payload is
therefore the FPP message in the causal trace package from those same stages.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedCausalPayloadIdentity

open SmzaRp05ExecutableMerkleVerifier (Program Oracle ask)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05AcceptedRoleLabels (CausalPayloads causalTrace
  current_inner_readback_of_recorded_chain global_payload_of_recorded_input)
open SmzaRp05CurrentAcceptedCausalPayloads
  (Records current_causal_payloads_and_targets_of_stages)
open SmzaRp05CurrentFppFrameReadback (successful_response_program_has_current_fpp_edge)
open SmzaRp05CurrentPiopFrameReadback
  (current_final_piop_edge)
open SmzaRp05CurrentDecsFrameReadback (current_decs_opening_edge406)
open SmzaRp05FilteredDecoderInstability (globalNormalizedPayload globalOnlineNext)
open SmzaRp05TracePrefixes (Payload payload)
open SmzaRp05PcsToFinalProgram (sameProofRows)
open SmzaRp05PcsHashFppMiddle (gammaRows)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript finalInput)
open V8Smz9PiopReconstruction (points)
open V8Smz9CoherentMerkleGeometry (extract)
open V8SmzaOracleParser (RawInput RawDigest)
open SmzaChallengeStageTargets (Role)

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

/-- A causal payload package is unique for a fixed namespace and trace: each
payload field is determined by its corresponding `Option.some` readback. -/
theorem causal_payloads_unique {ns : Namespace} {trace : SmzaRp05TracePrefixes.Trace}
    (left right : CausalPayloads ns trace) : left = right := by
  have decsEq : left.decs = right.decs :=
    Option.some.inj (left.decsRead.symm.trans right.decsRead)
  have piopEq : left.piop = right.piop :=
    Option.some.inj (left.piopRead.symm.trans right.piopRead)
  have fppEq : left.fpp = right.fpp :=
    Option.some.inj (left.fppRead.symm.trans right.fppRead)
  cases left with
  | mk ld lp lf ldr lpr lfr =>
      cases right with
      | mk rd rp rf rdr rpr rfr =>
          simp only at decsEq piopEq fppEq
          subst rd
          subst rp
          subst rf
          rfl

/-- A retained call's normalized FPP payload is the FPP message selected by
the same accepted stages' causal trace.  In particular, `input` is not a
caller-provided equality with the response-program input: membership in the
actual `hashProgram.record` and `responseBuilt` force it to be that input. -/
theorem retained_hash_call_has_causal_fpp_payload
    (ns : Namespace) (dsl : RelationDsl) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (sameProofRows execution.middle.pcs execution.piop) execution.decs
      (List.ofFn fun j : Fin 6 => points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending)
    [Fintype RawDigest]
    (records : Records) (collisionFree : SmzaRecordedTracePath.RecordsCollisionFree records)
    (openingRecorded : (pcs.openingInput, pcs.openingDigest) ∈ records)
    (finalRecorded : (finalInput transcript, wire.hPiop) ∈ records)
    (hashRecordRetained : ∀ call,
      call ∈ (pcs.hashProgram.record oracle).2 → call ∈ records)
    (input : RawInput) (inputRecorded : (input, execution.hashFpp) ∈
      (pcs.hashProgram.record oracle).2)
    (normalizedPayload : Payload)
    (payloadRead : globalNormalizedPayload ns input = some normalizedPayload) :
    ∃ messages : CausalPayloads ns
      (extract (globalOnlineNext ns) records 28 .decs pcs.openingDigest),
      messages.fpp = normalizedPayload := by
  classical
  obtain ⟨selectedInput, fppBytes, selectedAsk, _fppFramed, fppNormalized,
      fppNext, _payloadSuffix⟩ :=
    successful_response_program_has_current_fpp_edge ns pcs.post.root execution.decs
      (pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      (gammaRows pcs.post)
      (pcs.decsPoints.map SmzaRp05ExecutableRestore.toWord)
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      (SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement)
      pcs.hashProgram pcs.responseBuilt
  have singletonProgram : pcs.hashProgram = ask selectedInput := selectedAsk
  have callEq : (input, execution.hashFpp) =
      (selectedInput, oracle selectedInput) := by
    rw [singletonProgram] at inputRecorded
    simpa [Program.record, ask] using inputRecorded
  have inputEq : input = selectedInput := congrArg Prod.fst callEq
  subst input
  have payloadEq : normalizedPayload = ⟨.fpp, fppBytes⟩ := by
    have someEq : some normalizedPayload = some (⟨.fpp, fppBytes⟩ : Payload) :=
      payloadRead.symm.trans fppNormalized
    exact Option.some.inj someEq
  have rowsBuilt := pcs.openingBuilt
  obtain ⟨_decsRows, _rowsFormed, _decsFramed, _decsParsed, decsNext⟩ :=
    current_decs_opening_edge406 ns wire.hPiop pcs.heads
      execution.middle.pcs.rcombiTails pcs.openingInput rowsBuilt
  have piopNext := current_final_piop_edge ns transcript
  have transcriptHash : transcript.hashFpp = execution.hashFpp := by
    have projected := congrArg
      SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript.hashFpp
      execution.reconstructed
    simpa [SmzaRp05ExecutableReconstruction.reconstruct] using projected.symm
  have piopNext' : globalOnlineNext ns .piop (finalInput transcript) =
      some [(.fpp, execution.hashFpp)] := by
    simpa [transcriptHash] using piopNext
  have fppRecorded : (selectedInput, execution.hashFpp) ∈ records :=
    hashRecordRetained _ inputRecorded
  have causal := current_causal_payloads_and_targets_of_stages ns dsl statement
    pending nonce wire oracle transcript execution pcs records collisionFree
    openingRecorded finalRecorded hashRecordRetained
  obtain ⟨trace, traceEq, messages, _rootTarget, _piopTarget, _decsTarget⟩ := causal
  subst trace
  let roleTarget : Role → V8SmzaOracleParser.Stage × RawDigest
    | .decsMatrix => (.root, pcs.post.root)
    | .piopMatrix => (.fpp, execution.hashFpp)
    | .piopOpening => (.piop, wire.hPiop)
    | .decsSample => (.decs, pcs.openingDigest)
  have roleTargets :
      roleTarget .decsMatrix = (.root, pcs.post.root) ∧
      roleTarget .piopMatrix = (.fpp, execution.hashFpp) ∧
      roleTarget .piopOpening = (.piop, wire.hPiop) ∧
      roleTarget .decsSample = (.decs, pcs.openingDigest) := by
    exact ⟨rfl, rfl, rfl, rfl⟩
  have inner := current_inner_readback_of_recorded_chain ns records collisionFree
    pcs.openingDigest wire.hPiop execution.hashFpp pcs.post.root
    pcs.openingInput (finalInput transcript) selectedInput
    openingRecorded finalRecorded fppRecorded decsNext piopNext' fppNext
    28 (by omega) roleTarget roleTargets
  have fppNormalized' : globalNormalizedPayload ns selectedInput =
      some (⟨.fpp, fppBytes⟩ : Payload) := fppNormalized
  have fppValid :
      (V8SmzaOnlineParser.payloadNext .fpp (⟨.fpp, fppBytes⟩ : Payload)).isSome := by
    have next : V8SmzaOnlineParser.payloadNext .fpp
        (⟨.fpp, fppBytes⟩ : Payload) =
        some [(.root, pcs.post.root)] := by
      simpa [globalOnlineNext, fppNormalized'] using fppNext
    simp [next]
  have extractedFpp := global_payload_of_recorded_input ns records collisionFree
    .fpp execution.hashFpp selectedInput (⟨.fpp, fppBytes⟩ : Payload)
    fppRecorded fppNormalized'
    fppValid 28 (by omega)
  have sameTraceFpp :
      payload ns .fpp
        (extract (globalOnlineNext ns) records 28 .fpp execution.hashFpp) =
      some messages.fpp := by
    rw [inner .piopMatrix]
    simpa [causalTrace] using messages.fppRead
  have fppEq : (⟨.fpp, fppBytes⟩ : Payload) = messages.fpp :=
    Option.some.inj (extractedFpp.symm.trans sameTraceFpp)
  exact ⟨messages, (payloadEq.trans fppEq).symm⟩

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedCausalPayloadIdentity
