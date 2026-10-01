import SmzaRp05CurrentBranchOracleAgreement
import SmzaRp05PhysicalPcsRecordRetention
import SmzaRp05PhysicalHashFppRecordRetention
import SmzaRp05CurrentPrequeryChronology
import SmzaRp05CurrentAcceptedDecsMatrixCallReadback

/-! # Same-run current stage replay across agreeing oracles

This module transports the data fields of current verifier stages to a new
oracle. Agreement is required only on calls retained in the source verifier
record; the dependent stage records are rebuilt with those same data fields.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedStageReplay

open SmzaRp05ExecutableMerkleVerifier (Program Oracle ask)
open SmzaRp05ExecutablePcsClosure
  (ExecutionStages transcriptProgram canonicalOpening pcsProgram)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript finalize)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentBranchOracleAgreement (eval_eq_of_agrees_on_left_reads)
open SmzaRp05PhysicalPcsRecordRetention (execution_pcs_records_retained_in_verifier)
open SmzaRp05PhysicalHashFppRecordRetention (pcs_hash_fpp_records_retained)
open SmzaRp05CurrentPrequeryChronology (pcs_q38_record_split)
open SmzaRp05CurrentAcceptedDecsMatrixCallReadback (post_merkle_records_retained_in_pcs)
open SmzaRp05ExecutableChallengeStage (postMerkleProgram afterMerkle)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

/-- Recover the successful transcript-program result from the supplied
same-run data, without assuming an accepted final query. -/
theorem execution_transcript_success
    (ns : SmzaRp05LeafNamespace.Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript) :
    (transcriptProgram ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire).eval oracle = some transcript := by
  simp only [transcriptProgram, execution.decoded, Program.eval_bind]
  rw [execution.openingExecuted, Option.bind_some]
  rw [execution.pcsExecuted, Option.bind_some]
  rw [execution.matrixExecuted, Option.bind_some]
  simp [Program.eval, execution.reconstructed]

/-- A full verifier record equality induces pointwise answer agreement on
every call in its left record. This is the bridge used with the checked
same-branch grouped-claims record theorem. -/
theorem agrees_on_record_reads_of_record_eq
    {Result : Type} (program : Program Result) (left right : Oracle)
    (recordEq : program.record left = program.record right) :
    ∀ input, (input, left input) ∈ (program.record left).2 →
      left input = right input := by
  intro input member
  have second := congrArg Prod.snd recordEq
  have memberRight : (input, left input) ∈ (program.record right).2 := by
    rw [← second]
    exact member
  exact Program.recorded_call right program (input, left input) memberRight

/-- Replay the actual execution-stage data under another oracle agreeing on
the successful transcript's verifier reads. The matrix and PCS subprogram
logs are transported through the source `bind` tree; the final result is a
new dependent `ExecutionStages` value with the original stage data. -/
def replay_execution_stages_of_verifier_record_eq
    (ns : SmzaRp05LeafNamespace.Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView)
    (left right : Oracle) (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire left transcript)
    (recordEq :
    (verifierProgram ns dsl statement pending nonce wire).record left =
      (verifierProgram ns dsl statement pending nonce wire).record right) :
    ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire right transcript := by
  let full := verifierProgram ns dsl statement pending nonce wire
  have transcriptSuccess := execution_transcript_success ns dsl statement pending
    nonce wire left transcript execution
  have agree := agrees_on_record_reads_of_record_eq full left right recordEq
  let afterOpening : V8Smz9PiopSoundness.Opening × Bool → Program ReconstructedTranscript :=
    fun openingPair =>
      (pcsProgram ns openingPair.2 wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 =>
          V8Smz9PiopReconstruction.points openingPair.1 j)
        wire.salt statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        wire.tapes wire.paths).bind fun (hashFpp, pcsPending) =>
        (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
          pcsPending hashFpp).bind fun (matrix, finalPending) =>
          .done (some (SmzaRp05ExecutableReconstruction.reconstruct dsl statement
            matrix openingPair.1 execution.piop hashFpp finalPending))
  have transcriptForm : transcriptProgram ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire = (canonicalOpening pending nonce wire.hPiop).bind afterOpening := by
    simp [transcriptProgram, execution.decoded, afterOpening]
  have openingInTranscript :
      ((canonicalOpening pending nonce wire.hPiop).record left).2 ⊆
        ((transcriptProgram ns dsl statement pending statement.toBytes
          (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
          nonce wire).record left).2 := by
    rw [transcriptForm]
    exact Program.bind_log_left left (canonicalOpening pending nonce wire.hPiop)
      afterOpening (execution.opening, execution.openingPending)
      execution.openingExecuted
  have openingInVerifier :
      ((canonicalOpening pending nonce wire.hPiop).record left).2 ⊆
        (full.record left).2 := by
    intro call member
    exact Program.bind_log_left left
      (transcriptProgram ns dsl statement pending statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire)
      (finalize wire.hPiop) transcript transcriptSuccess (openingInTranscript member)
  have pcsInVerifier := execution_pcs_records_retained_in_verifier ns dsl statement
    pending nonce wire left transcript execution transcriptSuccess
  let matrixProgram := SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
    execution.pcsPending execution.hashFpp
  let matrixContinuation : RawDigest × Bool → Program ReconstructedTranscript :=
    fun pair => (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
      pair.2 pair.1).bind fun (matrix, finalPending) =>
      .done (some (SmzaRp05ExecutableReconstruction.reconstruct dsl statement
        matrix execution.opening execution.piop pair.1 finalPending))
  have matrixCallsInTranscript : (matrixProgram.record left).2 ⊆
      ((transcriptProgram ns dsl statement pending statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire).record left).2 := by
    rw [transcriptForm]
    have inMatrixBind : (matrixProgram.record left).2 ⊆
      ((matrixProgram.bind (fun (matrix, finalPending) =>
          .done (some (SmzaRp05ExecutableReconstruction.reconstruct dsl statement
            matrix execution.opening execution.piop execution.hashFpp finalPending)))).record left).2 :=
      Program.bind_log_left left matrixProgram
        (fun (matrix, finalPending) =>
          .done (some (SmzaRp05ExecutableReconstruction.reconstruct dsl statement
            matrix execution.opening execution.piop execution.hashFpp finalPending)))
        (execution.matrix, execution.finalPending) execution.matrixExecuted
    have inPcsBind := Program.bind_log_right left
      (pcsProgram ns execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        wire.tapes wire.paths)
      matrixContinuation (execution.hashFpp, execution.pcsPending)
      execution.pcsExecuted
    have matrixInPcs : (matrixProgram.record left).2 ⊆
        (((pcsProgram ns execution.openingPending wire.hPiop
          (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
          execution.decs
          (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
          wire.salt statement.toBytes
          (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
          wire.tapes wire.paths).bind matrixContinuation).record left).2 := by
      intro call member
      exact inPcsBind (inMatrixBind member)
    have inTranscript := Program.bind_log_right left
      (canonicalOpening pending nonce wire.hPiop) afterOpening
      (execution.opening, execution.openingPending) execution.openingExecuted
    intro call member
    exact inTranscript (matrixInPcs member)
  have matrixInVerifier : (matrixProgram.record left).2 ⊆ (full.record left).2 := by
    intro call member
    have intoTranscript := Program.bind_log_left left
      (transcriptProgram ns dsl statement pending statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire) (finalize wire.hPiop) transcript transcriptSuccess
    exact intoTranscript (matrixCallsInTranscript member)
  have openingEq := eval_eq_of_agrees_on_left_reads
    (canonicalOpening pending nonce wire.hPiop) left right
    (fun input member => agree input (openingInVerifier member))
  have pcsEq := eval_eq_of_agrees_on_left_reads
    (pcsProgram ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths) left right
    (fun input member => agree input (pcsInVerifier (input, left input) member))
  have matrixEq := eval_eq_of_agrees_on_left_reads matrixProgram left right
    (fun input member => agree input (matrixInVerifier member))
  refine {
    middle := execution.middle
    decs := execution.decs
    piop := execution.piop
    opening := execution.opening
    openingPending := execution.openingPending
    hashFpp := execution.hashFpp
    pcsPending := execution.pcsPending
    matrix := execution.matrix
    finalPending := execution.finalPending
    decoded := execution.decoded
    openingExecuted := ?_
    pcsExecuted := ?_
    matrixExecuted := ?_
    reconstructed := execution.reconstructed
  }
  · exact openingEq.symm.trans execution.openingExecuted
  · exact pcsEq.symm.trans execution.pcsExecuted
  · exact matrixEq.symm.trans execution.matrixExecuted

/-- Replay the intermediate PCS-stage data verbatim under a new oracle when
the complete verifier records agree. The PCS record split and its Merkle/hash
retention lemmas show that each dynamic subprogram's reads belong to that
same verifier record. -/
def replay_pcs_stages_of_verifier_record_eq
    (ns : SmzaRp05LeafNamespace.Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView)
    (left right : Oracle) (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire left transcript)
    (stages : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths left execution.hashFpp execution.pcsPending)
    (recordEq :
      (verifierProgram ns dsl statement pending nonce wire).record left =
        (verifierProgram ns dsl statement pending nonce wire).record right) :
    PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths right execution.hashFpp execution.pcsPending := by
  let full := verifierProgram ns dsl statement pending nonce wire
  have transcriptSuccess := execution_transcript_success ns dsl statement pending
    nonce wire left transcript execution
  have agree := agrees_on_record_reads_of_record_eq full left right recordEq
  have pcsInVerifier := execution_pcs_records_retained_in_verifier ns dsl statement
    pending nonce wire left transcript execution transcriptSuccess
  have pcsRecord := pcs_q38_record_split ns execution.openingPending wire.hPiop
    (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
    execution.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
    wire.salt statement.toBytes
    (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
    wire.tapes wire.paths left execution.hashFpp execution.pcsPending stages
  have openingAnswer : left stages.openingInput = stages.openingDigest := by
    simpa [ask, Program.eval] using stages.openingRead
  have queryInVerifier : ∀ call,
      call ∈ ((SmzaRp05ExecutablePcsClosure.queryProgram execution.openingPending
        stages.openingDigest).record left).2 → call ∈ (full.record left).2 := by
    intro call member
    have memberPcs : call ∈ ((SmzaRp05ExecutablePcsClosure.pcsProgram ns
        execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        wire.tapes wire.paths).record left).2 := by
      rw [pcsRecord]
      simp only [List.mem_append]
      exact Or.inr (Or.inl member)
    exact pcsInVerifier _ memberPcs
  have openingInVerifier :
      (stages.openingInput, left stages.openingInput) ∈ (full.record left).2 := by
    have memberPcs :
        (stages.openingInput, left stages.openingInput) ∈
          ((SmzaRp05ExecutablePcsClosure.pcsProgram ns execution.openingPending
            wire.hPiop
            (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
            execution.decs
            (List.ofFn fun j : Fin 6 =>
              V8Smz9PiopReconstruction.points execution.opening j)
            wire.salt statement.toBytes
            (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
            wire.tapes wire.paths).record left).2 := by
      rw [pcsRecord]
      simp [openingAnswer]
    exact pcsInVerifier (stages.openingInput, left stages.openingInput) memberPcs
  have postInVerifier : ∀ call,
      call ∈ ((postMerkleProgram ns stages.merkleInput).record left).2 →
        call ∈ (full.record left).2 := by
    intro call member
    have memberPcs := post_merkle_records_retained_in_pcs
      ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths left execution.hashFpp execution.pcsPending stages
      execution.pcsExecuted call member
    exact pcsInVerifier call memberPcs
  have hashInVerifier : ∀ call, call ∈ (stages.hashProgram.record left).2 →
      call ∈ (full.record left).2 := by
    intro call member
    have memberPcs := pcs_hash_fpp_records_retained ns execution.openingPending
      wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths left execution.hashFpp execution.pcsPending stages
      execution.pcsExecuted call.1 call.2 member
    exact pcsInVerifier call memberPcs
  have openingEq := eval_eq_of_agrees_on_left_reads (ask stages.openingInput)
    left right (by
      intro input member
      have sameInput : input = stages.openingInput := by
        have pairEq : (input, left input) =
            (stages.openingInput, left stages.openingInput) := by
          simpa [ask, Program.record] using member
        exact congrArg Prod.fst pairEq
      subst input
      exact agree _ openingInVerifier)
  have queryEq := eval_eq_of_agrees_on_left_reads
    (SmzaRp05ExecutablePcsClosure.queryProgram execution.openingPending stages.openingDigest)
    left right (fun input member =>
      agree input (queryInVerifier (input, left input) member))
  have postEq := eval_eq_of_agrees_on_left_reads
    (postMerkleProgram ns stages.merkleInput) left right
    (fun input member => agree input (postInVerifier (input, left input) member))
  have hashEq := eval_eq_of_agrees_on_left_reads stages.hashProgram left right
    (fun input member => agree input (hashInVerifier (input, left input) member))
  exact {
    heads := stages.heads
    openingInput := stages.openingInput
    openingDigest := stages.openingDigest
    indexes := stages.indexes
    sampledPending := stages.sampledPending
    decsPoints := stages.decsPoints
    rows := stages.rows
    merkleInput := stages.merkleInput
    post := stages.post
    hashProgram := stages.hashProgram
    headsBuilt := stages.headsBuilt
    openingBuilt := stages.openingBuilt
    openingRead := openingEq.symm.trans stages.openingRead
    queryExecuted := queryEq.symm.trans stages.queryExecuted
    pointsBuilt := stages.pointsBuilt
    rowsBuilt := stages.rowsBuilt
    inputBuilt := stages.inputBuilt
    postExecuted := postEq.symm.trans stages.postExecuted
    responseBuilt := stages.responseBuilt
    hashExecuted := hashEq.symm.trans stages.hashExecuted
    pendingReturned := stages.pendingReturned
  }

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedStageReplay
