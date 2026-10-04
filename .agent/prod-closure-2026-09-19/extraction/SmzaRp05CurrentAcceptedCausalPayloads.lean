import SmzaRp05AcceptedRoleLabels
import SmzaRp05CurrentDecsFrameReadback
import SmzaRp05CurrentFppFrameReadback
import SmzaRp05CurrentPiopFrameReadback
import SmzaRp05PhysicalCausalRecordReadback
import SmzaRp05PhysicalHashFppRecordRetention
import SmzaRp05PhysicalProducerVerifierPrefix
import SmzaRp05ExecutablePcsClosureStatement

/-! # Current accepted causal payloads

The current DECS, final PIOP, and response-hash FPP payloads are read back
from the actual successful PCS/verifier constructors.  Their query pairs
come from that same accepted physical run's full raw log; the resulting
current-parser trace package is therefore not assembled from independent
payload, edge, or execution witnesses.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedCausalPayloads

open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.CmsCompressedOracle (State Basis)
open HegemonCrypto.CmsOracleSimulation (globalDecompress)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle ask)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult rawLog basisOracle physicalRun)
open SmzaRp05PhysicalProducerVerifierPrefix
  (accepted_physical_producer_prefix_dichotomy)
open SmzaRp05PhysicalPcsRecordRetention
  (execution_pcs_records_retained_in_verifier)
open SmzaRp05CurrentPrequeryChronology (pcs_q38_record_split)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05FilteredDecoderInstability (globalNormalizedPayload globalOnlineNext)
open SmzaRp05CurrentFppFrameReadback
  (successful_response_program_has_current_fpp_edge)
open SmzaRp05CurrentPiopFrameReadback
  (current_final_normalized_payload current_final_piop_edge)
open SmzaRp05CurrentDecsFrameReadback (current_decs_opening_edge406)
open SmzaRp05AcceptedRoleLabels (CausalPayloads causal_payloads_of_recorded_chain)
open SmzaRecordedTracePath (RecordsCollisionFree)
open V8SmzaOracleParser (RawInput RawDigest)

local instance : DecidableEq RawInput :=
  SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000

abbrev Records := V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest
abbrev Payload := SmzaRp05TracePrefixes.Payload
local notation "Statement" => SmzaRp05StatementNamespace.Statement
local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

/-- On an actual staged execution, the payload labels follow from the
successful DECS-opening, response-hash, and final-query constructors.  The
three record memberships are explicitly those same stage calls; no parser
payload or edge is supplied independently. -/
theorem current_causal_payloads_of_stages
    (ns : Namespace) (dsl : RelationDsl) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending)
    [Fintype RawDigest]
    (records : Records) (collisionFree : RecordsCollisionFree records)
    (openingRecorded : (pcs.openingInput, pcs.openingDigest) ∈ records)
    (finalRecorded : (SmzaRp05ExecutableFinalVerifier.finalInput transcript,
      wire.hPiop) ∈ records)
    (hashRecordRetained : ∀ call,
      call ∈ (pcs.hashProgram.record oracle).2 → call ∈ records) :
    Nonempty (CausalPayloads ns
      (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) records 28
        .decs pcs.openingDigest)) := by
  have rowsBuilt := pcs.openingBuilt
  obtain ⟨decsRows, _rowsFormed, _decsFramed, decsParsed, decsNext⟩ :=
    current_decs_opening_edge406 ns wire.hPiop pcs.heads
      execution.middle.pcs.rcombiTails pcs.openingInput rowsBuilt
  have piopParsed := current_final_normalized_payload ns transcript
  have piopNext := current_final_piop_edge ns transcript
  obtain ⟨selectedInput, fppBytes, selectedAsk, _framed, fppParsed, fppNext⟩ :=
    successful_response_program_has_current_fpp_edge ns pcs.post.root execution.decs
      (pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)
      (pcs.decsPoints.map SmzaRp05ExecutableRestore.toWord)
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      (SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement)
      pcs.hashProgram pcs.responseBuilt
  rcases fppNext with ⟨fppNext, _fppPayloadSuffix⟩
  have hashCall : (selectedInput, execution.hashFpp) ∈
      (pcs.hashProgram.record oracle).2 := by
    rw [selectedAsk]
    have value : oracle selectedInput = execution.hashFpp := by
      have eval := pcs.hashExecuted
      rw [selectedAsk] at eval
      simpa [ask, Program.eval] using eval
    simp [ask, Program.record, value]
  have fppRecorded : (selectedInput, execution.hashFpp) ∈ records :=
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
  let decsPayload : Payload := ⟨.decs,
    (SmzaRp05ExecutableChallengeStage.digestWords wire.hPiop ++ decsRows).flatMap
      (HegemonCrypto.CanonicalBytes.encodeLE 8)⟩
  let piopPayload : Payload := ⟨.piop,
    SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩
  let fppPayload : Payload := ⟨.fpp, fppBytes⟩
  exact ⟨causal_payloads_of_recorded_chain ns records collisionFree
    pcs.openingDigest wire.hPiop execution.hashFpp pcs.post.root
    pcs.openingInput (SmzaRp05ExecutableFinalVerifier.finalInput transcript)
    selectedInput decsPayload piopPayload fppPayload openingRecorded finalRecorded
    fppRecorded decsParsed piopParsed fppParsed rfl rfl rfl decsNext piopNext'
    fppNext 28 (by omega)⟩

/-- The same staged causal constructor also exposes the three literal digest
prefixes carried by its DECS, final PIOP, and response-hash payloads.  This is
the target-byte interface for same-execution advice readback: callers do not
provide message digests independently of the accepted stages. -/
theorem current_causal_payloads_and_targets_of_stages
    (ns : Namespace) (dsl : RelationDsl) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending)
    [Fintype RawDigest]
    (records : Records) (collisionFree : RecordsCollisionFree records)
    (openingRecorded : (pcs.openingInput, pcs.openingDigest) ∈ records)
    (finalRecorded : (SmzaRp05ExecutableFinalVerifier.finalInput transcript,
      wire.hPiop) ∈ records)
    (hashRecordRetained : ∀ call,
      call ∈ (pcs.hashProgram.record oracle).2 → call ∈ records) :
    ∃ trace : SmzaRp05TracePrefixes.Trace,
      trace = V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) records
        28 .decs pcs.openingDigest ∧
      ∃ messages : CausalPayloads ns trace,
        V8SmzaOracleParser.digestAt messages.fpp.bytes 0 = pcs.post.root ∧
        V8SmzaOracleParser.digestAt messages.piop.bytes 0 = execution.hashFpp ∧
        V8SmzaOracleParser.digestAt messages.decs.bytes 0 = wire.hPiop := by
  have rowsBuilt := pcs.openingBuilt
  obtain ⟨decsRows, _rowsFormed, _decsFramed, decsParsed, decsNext⟩ :=
    current_decs_opening_edge406 ns wire.hPiop pcs.heads
      execution.middle.pcs.rcombiTails pcs.openingInput rowsBuilt
  have piopParsed := current_final_normalized_payload ns transcript
  have piopNext := current_final_piop_edge ns transcript
  obtain ⟨selectedInput, fppBytes, selectedAsk, _framed, fppParsed, fppNext⟩ :=
    successful_response_program_has_current_fpp_edge ns pcs.post.root execution.decs
      (pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)
      (pcs.decsPoints.map SmzaRp05ExecutableRestore.toWord)
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      (SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement)
      pcs.hashProgram pcs.responseBuilt
  rcases fppNext with ⟨fppNext, _fppPayloadSuffix⟩
  have hashCall : (selectedInput, execution.hashFpp) ∈
      (pcs.hashProgram.record oracle).2 := by
    rw [selectedAsk]
    have value : oracle selectedInput = execution.hashFpp := by
      have eval := pcs.hashExecuted
      rw [selectedAsk] at eval
      simpa [ask, Program.eval] using eval
    simp [ask, Program.record, value]
  have fppRecorded : (selectedInput, execution.hashFpp) ∈ records :=
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
  have fppTarget : V8SmzaOracleParser.digestAt fppBytes 0 = pcs.post.root := by
    unfold globalOnlineNext at fppNext
    rw [fppParsed] at fppNext
    simpa [V8SmzaOnlineParser.payloadNext] using fppNext
  let decsPayload : Payload := ⟨.decs,
    (SmzaRp05ExecutableChallengeStage.digestWords wire.hPiop ++ decsRows).flatMap
      (HegemonCrypto.CanonicalBytes.encodeLE 8)⟩
  let piopPayload : Payload := ⟨.piop,
    SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩
  let fppPayload : Payload := ⟨.fpp, fppBytes⟩
  let messages := causal_payloads_of_recorded_chain ns records collisionFree
    pcs.openingDigest wire.hPiop execution.hashFpp pcs.post.root
    pcs.openingInput (SmzaRp05ExecutableFinalVerifier.finalInput transcript)
    selectedInput decsPayload piopPayload fppPayload openingRecorded finalRecorded
    fppRecorded decsParsed piopParsed fppParsed rfl rfl rfl decsNext piopNext'
    fppNext 28 (by omega)
  refine ⟨V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) records 28
    .decs pcs.openingDigest, rfl, messages, ?_, ?_, ?_⟩
  · change V8SmzaOracleParser.digestAt fppBytes 0 = pcs.post.root
    exact fppTarget
  · change V8SmzaOracleParser.digestAt
      (SmzaRp05ExecutableFinalVerifier.finalPayload transcript) 0 = execution.hashFpp
    change V8Smz9CoherentMerkleGeometry.digestAt (List.ofFn transcript.hashFpp ++ _)
      0 = execution.hashFpp
    rw [SmzaRp05ExecutableMerkleVerifier.digest_at_ofFn_append]
    exact transcriptHash
  · change V8SmzaOracleParser.digestAt
      ((SmzaRp05ExecutableChallengeStage.digestWords wire.hPiop ++ decsRows).flatMap
        (HegemonCrypto.CanonicalBytes.encodeLE 8)) 0 = wire.hPiop
    rw [List.flatMap_append,
      SmzaRp05CurrentDecsFrameReadback.digest_words_encode_exact]
    exact SmzaRp05ExecutableMerkleVerifier.digest_at_ofFn_append wire.hPiop _

/-- Actual accepted physical execution instantiates the generic constructor
lemma with its same-branch raw log. The raw split comes from the accepted
physical producer/verifier execution; PCS and final-query chronology lift
the actual DECS and PIOP calls, while the response-hash theorem lifts every
actual FPP-program call. -/
theorem accepted_physical_current_causal_payloads
    {Key Phase Work : Type}
    [Fintype Key] [DecidableEq Key]
    [Fintype RawDigest] [AddCommGroup RawDigest]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Work] [DecidableEq Work]
    (encode : RawInput → Key) (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches (fun (_ : RawInput) (answer : RawDigest) => answer)
      (producer.bind fun wire =>
        SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
          pending nonce wire))
    (state : State Key RawDigest Phase Work)
    (basis : Basis Key RawDigest Phase Work) (fallback : RawDigest)
    (nonzero : globalDecompress
      (physicalRun encode (fun (_ : RawInput) (answer : RawDigest) => answer)
        (producer.bind fun wire =>
          SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
            pending nonce wire) branch state) basis ≠ 0)
    (accepted : branchResult (fun (_ : RawInput) (answer : RawDigest) => answer)
      (producer.bind fun wire =>
        SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
          pending nonce wire) branch = some ())
    (collisionFree : RecordsCollisionFree
      (rawLog (fun (_ : RawInput) (answer : RawDigest) => answer)
        (producer.bind fun wire =>
          SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
            pending nonce wire) branch).toFinset) :
    ∃ wire transcript,
      ∃ execution : ExecutionStages ns dsl statement pending statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire
        (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
          basis fallback) transcript,
      ∃ pcs : PcsStages ns execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        wire.tapes wire.paths
        (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
          basis fallback)
        execution.hashFpp execution.pcsPending,
      Nonempty (CausalPayloads ns
        (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
          (rawLog (fun (_ : RawInput) (answer : RawDigest) => answer)
            (producer.bind fun wire =>
              SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
                pending nonce wire) branch).toFinset 28 .decs pcs.openingDigest)) := by
  let decode : RawInput → RawDigest → RawDigest :=
    fun (_ : RawInput) (answer : RawDigest) => answer
  let oracle := basisOracle encode decode basis fallback
  let program := producer.bind fun wire =>
    SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
      pending nonce wire
  obtain ⟨wire0, producerSuccess0, _verifierAccepted0, rawSplit0, _event⟩ :=
    accepted_physical_producer_prefix_dichotomy encode producer ns dsl statement
      pending nonce branch state basis fallback nonzero accepted
  obtain ⟨wire, transcript, execution, pcs, producerSuccess, verifierAccepted,
      transcriptSuccess, hashRetained⟩ :=
    SmzaRp05PhysicalHashFppRecordRetention.accepted_physical_run_hash_fpp_records_in_raw_log
      encode producer ns dsl statement pending nonce branch state basis fallback
      nonzero accepted
  have wireEq : wire0 = wire := Option.some.inj
    (producerSuccess0.symm.trans producerSuccess)
  subst wire0
  have rawSplit : rawLog decode program branch =
      (producer.record oracle).2 ++
        ((SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
          pending nonce wire).record oracle).2 := by
    simpa [decode, oracle, program] using rawSplit0
  have pcsRetained := execution_pcs_records_retained_in_verifier ns dsl statement
    pending nonce wire oracle transcript execution transcriptSuccess
  have openingInPcs : (pcs.openingInput, pcs.openingDigest) ∈
      ((SmzaRp05ExecutablePcsClosure.pcsProgram ns execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        wire.tapes wire.paths).record oracle).2 := by
    rw [pcs_q38_record_split ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending pcs]
    simp
  have openingInVerifier := pcsRetained (pcs.openingInput, pcs.openingDigest)
    openingInPcs
  obtain ⟨acceptedTranscript, acceptedTranscriptSuccess, _clean, _hashEq,
      finalMember⟩ :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl
      statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle verifierAccepted
  have transcriptEq : acceptedTranscript = transcript :=
    Option.some.inj (acceptedTranscriptSuccess.symm.trans transcriptSuccess)
  subst acceptedTranscript
  let records : Records := (rawLog decode program branch).toFinset
  have openingRaw : (pcs.openingInput, pcs.openingDigest) ∈ rawLog decode program branch := by
    rw [rawSplit]
    exact List.mem_append.mpr (Or.inr openingInVerifier)
  have finalRaw : (SmzaRp05ExecutableFinalVerifier.finalInput transcript, wire.hPiop) ∈
      rawLog decode program branch := by
    rw [rawSplit]
    exact List.mem_append.mpr (Or.inr finalMember)
  have openingInRecords : (pcs.openingInput, pcs.openingDigest) ∈ records :=
    List.mem_toFinset.mpr openingRaw
  have finalInRecords : (SmzaRp05ExecutableFinalVerifier.finalInput transcript,
      wire.hPiop) ∈ records := List.mem_toFinset.mpr finalRaw
  have fppRecordRetained : ∀ call,
      call ∈ (pcs.hashProgram.record oracle).2 → call ∈ records := by
    intro call member
    have retained := hashRetained call member
    exact List.mem_toFinset.mpr retained
  exact ⟨wire, transcript, execution, pcs,
    current_causal_payloads_of_stages ns dsl statement pending nonce wire oracle
    transcript execution pcs records collisionFree openingInRecords finalInRecords
    fppRecordRetained⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedCausalPayloads
