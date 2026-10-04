import SmzaRp05CurrentCausalNonchallengeRetention
import SmzaRp05AcceptedRoleLabels

/-! # Root trace identity from the same accepted stages

The causal DECS trace and the root trace consumed by the current classifier
are connected by the actual recorded DECS/PIOP/FPP parser chain.  The three
retained records are recovered from the accepted verifier execution using
only nonchallenge-log retention.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRootTraceReadback

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableMerkleVerifier (Oracle Program ask)
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
open SmzaRp05CurrentPiopFrameReadback (current_final_piop_edge)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext)
open SmzaRp05AcceptedRoleLabels
  (causalTrace global_recorded_decs_chain global_sufficient_fuel_same_trace)
open SmzaRecordedTracePath (RecordsCollisionFree)
open V8SmzaOracleParser (RawInput RawDigest)

local instance : DecidableEq RawInput :=
  SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

/-- On the same accepted staged execution, the exact root subtrace below the
DECS causal trace equals the root extraction used by the classifier at any
sufficient fuel. No root-trace equality or parser edge is supplied by the
caller. -/
theorem actual_accepted_stages_causal_root_trace_eq
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
    (verifierAccepted :
      (verifierProgram ns dsl statement pending nonce wire).eval oracle = some ())
    (transcriptSuccess :
      (transcriptProgram ns dsl statement pending statement.toBytes
        (statementBindingWords statement) nonce wire).eval oracle = some transcript)
    (nonchallengeRetained : ∀ call,
      call ∈ ((verifierProgram ns dsl statement pending nonce wire).record oracle).2 →
      SmzaChallengeStageTargets.parseStageQuery call.1 = none → call ∈ records)
    (fuel : Nat) (enough : 25 ≤ fuel) :
    causalTrace
        (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) records
          28 .decs pcs.openingDigest) .decsMatrix =
      V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) records
        fuel .root pcs.post.root := by
  obtain ⟨openingRecorded, finalRecorded, hashRecordRetained⟩ :=
    accepted_execution_causal_record_memberships ns dsl statement pending nonce wire
      oracle transcript execution pcs records verifierAccepted transcriptSuccess
      nonchallengeRetained
  obtain ⟨decsRows, _rowsFormed, _decsFramed, _decsParsed, decsNext⟩ :=
    current_decs_opening_edge406 ns wire.hPiop pcs.heads
      execution.middle.pcs.rcombiTails pcs.openingInput pcs.openingBuilt
  have piopNext := current_final_piop_edge ns transcript
  obtain ⟨fppInput, _fppBytes, selectedAsk, _fppFramed, _fppParsed,
      fppNext, _payloadSuffix⟩ :=
    successful_response_program_has_current_fpp_edge ns pcs.post.root execution.decs
      (pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)
      (pcs.decsPoints.map SmzaRp05ExecutableRestore.toWord)
      (statementBindingWords statement)
      (SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement)
      pcs.hashProgram pcs.responseBuilt
  have hashCall : (fppInput, execution.hashFpp) ∈
      (pcs.hashProgram.record oracle).2 := by
    rw [selectedAsk]
    have value : oracle fppInput = execution.hashFpp := by
      have executed := pcs.hashExecuted
      rw [selectedAsk] at executed
      simpa [ask, Program.eval] using executed
    simp [ask, Program.record, value]
  have fppRecorded : (fppInput, execution.hashFpp) ∈ records :=
    hashRecordRetained _ hashCall
  have transcriptHash : transcript.hashFpp = execution.hashFpp := by
    have projected := congrArg
      SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript.hashFpp
      execution.reconstructed
    simpa [SmzaRp05ExecutableReconstruction.reconstruct] using projected.symm
  have piopNext' : globalOnlineNext ns .piop
      (SmzaRp05ExecutableFinalVerifier.finalInput transcript) =
        some [(.fpp, execution.hashFpp)] := by
    simpa [transcriptHash] using piopNext
  have chain := global_recorded_decs_chain ns records collisionFree
    pcs.openingDigest wire.hPiop execution.hashFpp pcs.post.root
    pcs.openingInput (SmzaRp05ExecutableFinalVerifier.finalInput transcript) fppInput
    openingRecorded finalRecorded fppRecorded decsNext piopNext' fppNext 28 (by omega)
  rw [chain]
  simp only [causalTrace, SmzaRp05TracePrefixes.child]
  exact global_sufficient_fuel_same_trace ns records 28 fuel .root pcs.post.root
    (by norm_num [SmzaRawTraceDepth.stageDepth])
    (by norm_num [SmzaRawTraceDepth.stageDepth]; omega)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRootTraceReadback
