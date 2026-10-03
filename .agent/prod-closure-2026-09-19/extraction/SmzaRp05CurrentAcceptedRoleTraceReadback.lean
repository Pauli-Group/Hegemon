import SmzaRp05CurrentAcceptedRootTraceReadback
import SmzaRp05CurrentCausalNonchallengeRetention
import SmzaRp05AcceptedRoleLabels
import SmzaRp05CurrentRoleLabels
import SmzaRp05CurrentAcceptedOuterReadback
import SmzaRp05CertifiedReplayScheduleFrames
import SmzaRp05CurrentExecutedMatrixReadback

/-! # Accepted DECS-matrix role trace facts

This is a lower-level same-execution bridge for the selected DECS matrix
role. It derives the sampled-counter parser target, the causal/root trace
identity, and the canonical outer preamble from the actual accepted PCS
constructors and retained verifier records. It does not yet claim membership
in the filtered dynamic role event.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRoleTraceReadback

open HegemonCrypto.CanonicalBytes (Byte)
open SmzaRp05ExecutableMerkleVerifier (Oracle)
open SmzaRp05ExecutablePcsClosure (ExecutionStages transcriptProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureStatement (statementBindingWords verifierProgram)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentAcceptedCausalPayloads (Records)
open SmzaRp05CurrentCausalNonchallengeRetention
  (accepted_execution_causal_record_memberships)
open SmzaRp05CurrentFppFrameReadback (successful_response_program_has_current_fpp_edge)
open SmzaRp05CurrentDecsFrameReadback (current_decs_opening_edge406)
open SmzaRp05CurrentPiopFrameReadback
  (current_final_normalized_payload current_final_piop_edge)
open SmzaRp05CurrentAcceptedOuterReadback (successful_pcs_root_query_readback)
open SmzaRp05CurrentAcceptedOuterReadback (successful_merkle_root_recorded)
open SmzaRp05ExecutableMerkleVerifier (Input shapeValid)
open SmzaRp05ExecutableChallengeStage (post_merkle_has_executed_core)
open SmzaRp05CurrentAcceptedRootTraceReadback (actual_accepted_stages_causal_root_trace_eq)
open SmzaRp05AcceptedRoleLabels
  (causalTrace current_outer_readback_of_recorded_chain
    current_inner_readback_of_recorded_chain global_sufficient_fuel_same_trace)
open SmzaRp05CurrentRoleLabels (preambleFromTrace)
open SmzaRp05FilteredDecoderInstability (globalNormalizedPayload globalOnlineNext)
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRp05CertifiedReplaySchedule (ordinary_counter_roundtrip)
open SmzaRecordedTracePath (RecordsCollisionFree)
open HegemonCrypto.SmallWoodTranscript (decsCoefficientDomain)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

local instance : DecidableEq RawInput :=
  SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq

local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

/-- Every literal DECS-matrix counter input from the accepted post-Merkle
stage parses as the exact role, target root, and counter used to construct
it. -/
theorem accepted_decs_matrix_counter_parses
    (root : RawDigest) (counter : Fin (2 ^ 64)) :
    parseStageQuery
      (SmzaRp05ExecutableChallengeStage.counterInput decsCoefficientDomain root
        counter.val) =
      some ⟨.decsMatrix, root, 0, counter.val⟩ := by
  simpa only [SmzaRp05ExecutableChallengeStage.counterInput,
    SmzaChallengeStageTargets.roleDomain] using
      ordinary_counter_roundtrip .decsMatrix (by decide) root counter

/-- The DECS-matrix selected root trace and its outer statement preamble are
read back from this exact accepted `ExecutionStages`/`PcsStages` pair. The
only retention premise is parse-none verifier-log retention; individual
DECS/PIOP/FPP/root memberships are derived. The unfiltered inner extraction
identity is returned as a useful intermediate for constructing the dynamic
event's statement-filtered trace. -/
theorem accepted_decs_matrix_root_trace_and_outer_preamble
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending)
    [Fintype RawDigest]
    (records : Records) (collisionFree : RecordsCollisionFree records)
    (verifierAccepted : (verifierProgram ns dsl statement pending nonce wire).eval oracle =
      some ())
    (transcriptSuccess : (transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire).eval oracle = some transcript)
    (nonchallengeRetained : ∀ call,
      call ∈ ((verifierProgram ns dsl statement pending nonce wire).record oracle).2 →
      parseStageQuery call.1 = none → call ∈ records)
    (fuel : Nat) (enough : 28 ≤ fuel) :
    let trace := V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
      records 28 .decs pcs.openingDigest
    causalTrace trace .decsMatrix =
        V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
          records fuel .root pcs.post.root ∧
      preambleFromTrace ns .decsMatrix
        (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
          records fuel .root pcs.post.root) = some statement.toBytes ∧
      (∀ role, preambleFromTrace ns role
        (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) records fuel
          (match role with
            | .decsMatrix => .root
            | .piopMatrix => .fpp
            | .piopOpening => .piop
            | .decsSample => .decs)
          (match role with
            | .decsMatrix => pcs.post.root
            | .piopMatrix => execution.hashFpp
            | .piopOpening => wire.hPiop
            | .decsSample => pcs.openingDigest)) = some statement.toBytes) ∧
      (∀ role, V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
        records fuel
        (match role with
          | .decsMatrix => .root
          | .piopMatrix => .fpp
          | .piopOpening => .piop
          | .decsSample => .decs)
        (match role with
          | .decsMatrix => pcs.post.root
          | .piopMatrix => execution.hashFpp
          | .piopOpening => wire.hPiop
          | .decsSample => pcs.openingDigest) = causalTrace trace role) := by
  classical
  obtain ⟨openingRecorded, finalRecorded, hashRecordRetained⟩ :=
    accepted_execution_causal_record_memberships ns dsl statement pending nonce wire
      oracle transcript execution pcs records verifierAccepted transcriptSuccess
      nonchallengeRetained
  obtain ⟨treeRoot, rootNormalized, rootSuffix, rootNext, rootVerifierMember⟩ :=
    successful_pcs_root_query_readback ns dsl statement pending nonce wire oracle
      transcript execution pcs transcriptSuccess
  let rootInput := SmzaRp05ExecutableMerkleVerifier.rootInput
    pcs.merkleInput.salt pcs.merkleInput.binding treeRoot
  let rootPayload : SmzaRp05TracePrefixes.Payload :=
    ⟨.root, pcs.merkleInput.salt ++ List.ofFn treeRoot ++ pcs.merkleInput.binding⟩
  have rootNone : parseStageQuery rootInput = none := by
    cases parsed : parseStageQuery rootInput with
    | none => rfl
    | some query =>
        have noNormalized :=
          SmzaRp05ChallengeRecordErasure.parse_stage_query_global_payload_none
            ns rootInput query parsed
        rw [rootNormalized] at noNormalized
        cases noNormalized
  have rootRecorded : (rootInput, pcs.post.root) ∈ records :=
    nonchallengeRetained (rootInput, pcs.post.root) rootVerifierMember rootNone
  have rootValid :
      (V8SmzaOnlineParser.payloadNext .root rootPayload).isSome := by
    have parsedNext : V8SmzaOnlineParser.payloadNext .root rootPayload =
        some [(.tree 23, treeRoot)] := by
      have next := rootNext
      unfold globalOnlineNext at next
      rw [rootNormalized] at next
      exact next
    rw [parsedNext]
    rfl
  obtain ⟨decsRows, rowsFormed, _decsFramed, decsNormalized, decsNext⟩ :=
    current_decs_opening_edge406 ns wire.hPiop pcs.heads
      execution.middle.pcs.rcombiTails pcs.openingInput pcs.openingBuilt
  let decsPayload : SmzaRp05TracePrefixes.Payload :=
    ⟨.decs, (SmzaRp05ExecutableChallengeStage.digestWords wire.hPiop ++ decsRows).flatMap
      (HegemonCrypto.CanonicalBytes.encodeLE 8)⟩
  have piopNormalized := current_final_normalized_payload ns transcript
  have transcriptHash : transcript.hashFpp = execution.hashFpp := by
    have projected := congrArg
      SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript.hashFpp
      execution.reconstructed
    simpa [SmzaRp05ExecutableReconstruction.reconstruct] using projected.symm
  have piopNext : globalOnlineNext ns .piop
      (SmzaRp05ExecutableFinalVerifier.finalInput transcript) =
      some [(.fpp, execution.hashFpp)] := by
    simpa [transcriptHash] using current_final_piop_edge ns transcript
  obtain ⟨fppInput, fppBytes, selectedAsk, _fppFramed, fppNormalized,
      fppNext, suffixWords⟩ :=
    successful_response_program_has_current_fpp_edge ns pcs.post.root execution.decs
      (pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)
      (pcs.decsPoints.map fun point => SmzaRp05ExecutableRestore.toWord point)
      (statementBindingWords statement)
      (SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement)
      pcs.hashProgram pcs.responseBuilt
  let fppPayload : SmzaRp05TracePrefixes.Payload := ⟨.fpp, fppBytes⟩
  have fppValue : oracle fppInput = execution.hashFpp := by
    have executed := pcs.hashExecuted
    rw [selectedAsk] at executed
    simpa [SmzaRp05ExecutableMerkleVerifier.ask,
      SmzaRp05ExecutableMerkleVerifier.Program.eval] using executed
  have fppInProgram : (fppInput, execution.hashFpp) ∈
      (pcs.hashProgram.record oracle).2 := by
    rw [selectedAsk]
    simp [SmzaRp05ExecutableMerkleVerifier.ask,
      SmzaRp05ExecutableMerkleVerifier.Program.record, fppValue]
  have fppRecorded : (fppInput, execution.hashFpp) ∈ records :=
    hashRecordRetained (fppInput, execution.hashFpp) fppInProgram
  have fppStatement : fppBytes.drop 16304 = statement.toBytes := by
    rw [suffixWords]
    exact SmzaRp05CurrentAcceptedOuterReadback.statement_binding_words_encode_exact
      statement
  have statementCanonical : ns.canonicalPreamble statement.toBytes = true := by
    have core := post_merkle_has_executed_core ns oracle pcs.merkleInput pcs.post
      pcs.postExecuted
    obtain ⟨shapeOk, _root, _recorded⟩ :=
      successful_merkle_root_recorded ns oracle pcs.merkleInput pcs.post.root core.1
    have bindingEq : pcs.merkleInput.binding = statement.toBytes := by
      have built := pcs.inputBuilt
      unfold SmzaRp05PcsMerklePayload.makeMerkleInput at built
      split at built
      · simp at built
      · have fields := Option.some.inj built
        exact (congrArg Input.binding fields).symm
    have h := shapeOk
    simp only [shapeValid, Bool.and_eq_true, decide_eq_true_eq] at h
    simpa [bindingEq] using h.1
  let target : Role → V8SmzaOracleParser.Stage × RawDigest := fun role =>
    match role with
    | .decsMatrix => (.root, pcs.post.root)
    | .piopMatrix => (.fpp, execution.hashFpp)
    | .piopOpening => (.piop, wire.hPiop)
    | .decsSample => (.decs, pcs.openingDigest)
  have targets : target .decsMatrix = (.root, pcs.post.root) ∧
      target .piopMatrix = (.fpp, execution.hashFpp) ∧
      target .piopOpening = (.piop, wire.hPiop) ∧
      target .decsSample = (.decs, pcs.openingDigest) := by
    exact ⟨rfl, rfl, rfl, rfl⟩
  have outer := current_outer_readback_of_recorded_chain ns records collisionFree
    pcs.openingDigest wire.hPiop execution.hashFpp pcs.post.root
    pcs.openingInput (SmzaRp05ExecutableFinalVerifier.finalInput transcript) fppInput
    rootInput decsPayload ⟨.piop, SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩
    fppPayload rootPayload openingRecorded finalRecorded fppRecorded rootRecorded
    decsNormalized piopNormalized fppNormalized rootNormalized rfl rfl rfl rfl
    decsNext piopNext fppNext rootValid statement.toBytes rootSuffix
    fppStatement statementCanonical statementCanonical
    fuel (by omega) target targets
  have inner := current_inner_readback_of_recorded_chain ns records collisionFree
    pcs.openingDigest wire.hPiop execution.hashFpp pcs.post.root
    pcs.openingInput (SmzaRp05ExecutableFinalVerifier.finalInput transcript) fppInput
    openingRecorded finalRecorded fppRecorded decsNext piopNext fppNext fuel
    (by omega) target targets
  have fuelTrace := global_sufficient_fuel_same_trace ns records fuel 28
    .decs pcs.openingDigest
    (by norm_num [SmzaRawTraceDepth.stageDepth]; omega)
    (by norm_num [SmzaRawTraceDepth.stageDepth])
  have traceEq := actual_accepted_stages_causal_root_trace_eq ns dsl statement pending
    nonce wire oracle transcript execution pcs records collisionFree verifierAccepted
    transcriptSuccess nonchallengeRetained fuel (by omega)
  dsimp only
  refine ⟨traceEq, outer .decsMatrix, ?_, ?_⟩
  · intro role
    cases role with
    | decsMatrix => exact outer .decsMatrix
    | piopMatrix => exact outer .piopMatrix
    | piopOpening => exact outer .piopOpening
    | decsSample => exact outer .decsSample
  · intro role
    cases role with
    | decsMatrix =>
        simpa [target] using (inner .decsMatrix).trans
          (congrArg (fun trace => causalTrace trace .decsMatrix) fuelTrace)
    | piopMatrix =>
        simpa [target] using (inner .piopMatrix).trans
          (congrArg (fun trace => causalTrace trace .piopMatrix) fuelTrace)
    | piopOpening =>
        simpa [target] using (inner .piopOpening).trans
          (congrArg (fun trace => causalTrace trace .piopOpening) fuelTrace)
    | decsSample =>
        simpa [target] using (inner .decsSample).trans
          (congrArg (fun trace => causalTrace trace .decsSample) fuelTrace)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRoleTraceReadback
