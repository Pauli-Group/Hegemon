import SmzaRp05PhysicalPcsRecordRetention
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentOpeningAttemptRetention

/-! The canonical opening subprogram runs before PCS.  This module exposes
the exact same-execution record path needed to feed its nonce reads to the
current fixed-advice decoders. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFixedAdviceOpeningSource

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutablePcsClosure (ExecutionStages canonicalOpening transcriptProgram)
open SmzaRp05ExecutablePcsClosureStatement (statementBindingWords verifierProgram)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript finalize)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentOpeningAttemptRetention
  (successful_canonical_opening_retains_failed_nonce_calls)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches answerLog rawLog branchResult)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)

noncomputable section
set_option autoImplicit false

/-- Every call made by the actual canonical-opening stage is retained in
the same assembled verifier record.  The continuation is the actual PCS
and matrix execution from `stages`; no replacement opening run is used. -/
theorem canonical_opening_records_retained_in_verifier
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
    (stages : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire oracle transcript)
    (transcriptSuccess :
      (transcriptProgram ns dsl statement pending statement.toBytes
        (statementBindingWords statement) nonce wire).eval oracle = some transcript) :
    ∀ call, call ∈ ((canonicalOpening pending nonce wire.hPiop).record oracle).2 →
      call ∈ ((verifierProgram ns dsl statement pending nonce wire).record oracle).2 := by
  let afterOpening : V8Smz9PiopSoundness.Opening × Bool →
      Program ReconstructedTranscript := fun openingPair =>
    let opening := openingPair.1
    let openingPending := openingPair.2
    (SmzaRp05ExecutablePcsClosure.pcsProgram ns openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows stages.middle.pcs stages.piop)
      stages.decs
      (List.ofFn fun j : Fin 6 =>
        V8Smz9PiopReconstruction.points opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths).bind fun (hashFpp, pcsPending) =>
        (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
          pcsPending hashFpp).bind fun (matrix, finalPending) =>
            .done (some (SmzaRp05ExecutableReconstruction.reconstruct dsl statement
              matrix opening stages.piop hashFpp finalPending))
  have transcriptForm : transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire =
      (canonicalOpening pending nonce wire.hPiop).bind afterOpening := by
    simp only [transcriptProgram, stages.decoded, afterOpening]
  have inTranscript : ∀ call,
      call ∈ ((canonicalOpening pending nonce wire.hPiop).record oracle).2 →
        call ∈ ((transcriptProgram ns dsl statement pending statement.toBytes
          (statementBindingWords statement) nonce wire).record oracle).2 := by
    intro call member
    rw [transcriptForm]
    exact Program.bind_log_left oracle
      (canonicalOpening pending nonce wire.hPiop) afterOpening
      (stages.opening, stages.openingPending) stages.openingExecuted member
  intro call member
  have throughTranscript := inTranscript call member
  have throughVerifier := Program.bind_log_left oracle
    (transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire)
    (finalize wire.hPiop) transcript transcriptSuccess throughTranscript
  simpa only [verifierProgram,
    SmzaRp05ExecutablePcsClosureStatement.verifierProgram,
    SmzaRp05ExecutablePcsClosure.verifierProgram] using throughVerifier

/-- Convert a raw program-record pair into the actual branch's answer-log
call.  The only bridge premise is the same-program `record_eq_of_branch_answers`
identity; it does not posit an independently sampled answer or database cell. -/
theorem verifier_record_pair_has_branch_answer
    {Result Key : Type} [Fintype Key] [DecidableEq Key]
    (program : Program Result)
    (branch : Branches groupedDecode program) (oracle : Oracle)
    (recordEq : program.record oracle =
      (branchResult groupedDecode program branch, rawLog groupedDecode program branch))
    (input : RawInput) (digest : RawDigest)
    (member : (input, digest) ∈ (program.record oracle).2) :
    ∃ output, (input, output) ∈ answerLog groupedDecode program branch ∧
      groupedDecode input output = digest := by
  have rawMember : (input, digest) ∈ rawLog groupedDecode program branch := by
    rw [recordEq] at member
    exact member
  obtain ⟨call, callMember, pairEq⟩ := List.mem_map.mp rawMember
  have inputEq : call.1 = input := congrArg Prod.fst pairEq
  have digestEq : groupedDecode call.1 call.2 = digest := congrArg Prod.snd pairEq
  subst input
  exact ⟨call.2, callMember, digestEq⟩

/-- Direct form for opening-role consumers: an actual opening-attempt record
pair becomes a call in the same verifier branch's answer log, with its
literal grouped digest. -/
theorem canonical_opening_record_pair_has_branch_answer
    {Key : Type} [Fintype Key] [DecidableEq Key]
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
    (stages : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire oracle transcript)
    (transcriptSuccess :
      (transcriptProgram ns dsl statement pending statement.toBytes
        (statementBindingWords statement) nonce wire).eval oracle = some transcript)
    (branch : Branches groupedDecode
      (verifierProgram ns dsl statement pending nonce wire))
    (recordEq : (verifierProgram ns dsl statement pending nonce wire).record oracle =
      (branchResult groupedDecode _ branch, rawLog groupedDecode _ branch))
    (input : RawInput) (digest : RawDigest)
    (member : (input, digest) ∈
      ((canonicalOpening pending nonce wire.hPiop).record oracle).2) :
    ∃ output,
      (input, output) ∈ answerLog groupedDecode
        (verifierProgram ns dsl statement pending nonce wire) branch ∧
      groupedDecode input output = digest := by
  apply verifier_record_pair_has_branch_answer (Key := Key)
    (verifierProgram ns dsl statement pending nonce wire) branch oracle recordEq
    input digest
  exact canonical_opening_records_retained_in_verifier ns dsl statement pending
    nonce wire oracle transcript stages transcriptSuccess (input, digest) member

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentFixedAdviceOpeningSource
