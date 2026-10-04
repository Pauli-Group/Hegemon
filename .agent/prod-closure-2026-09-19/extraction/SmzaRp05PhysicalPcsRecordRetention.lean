import SmzaRp05ExecutablePcsClosureStages
import SmzaRp05ExecutableMerkleMeasured
import SmzaRp05ExecutableMerklePaths
import SmzaRp05PhysicalProducerVerifierPrefix

/-!
# Same-run PCS log retention for the accepted Merkle subprogram

The PCS stage object records the actual Merkle input and post-Merkle result.
Together with successful evaluation of the source `pcsProgram` (which is
needed to establish that its LVCS/FiveMCA rejection gates passed), these facts
place every accepted Merkle-attempt record in the containing PCS program's
ordered record. This is the first compositional step toward using one
physical raw log as the readback relation for the full verifier.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05PhysicalPcsRecordRetention

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableMerkleVerifier (Program Oracle Input ask recordedAttempt merkleProgram)
open SmzaRp05ExecutablePcsClosure
  (pcsProgram queryProgram widths deltas nativeFiveMcaGate406 currentTwelveLvcsGate406
    ExecutionStages transcriptProgram canonicalOpening)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutableChallengeStage (postMerkleProgram afterMerkle)
open SmzaRp05PcsWireProjection (DecodedMiddleWire fieldWordsToGoldilocks)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05ExecutablePcsClosureStatement (statementBindingWords)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches physicalRun branchResult rawLog basisOracle)
open HegemonCrypto.CmsCompressedOracle (State Basis)
open HegemonCrypto.CmsOracleSimulation (globalDecompress)
open HegemonCrypto.SmallWood (Goldilocks)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false

/-- All records from the actual Merkle attempt in a successful `PcsStages`
run occur in the ordered record of the containing `pcsProgram`. The explicit
`executed` premise is essential: `PcsStages` stores the intermediate
calculations but not the acceptance bits of the executable LVCS/FiveMCA gates.
-/
theorem pcs_merkle_records_retained
    (ns : Namespace) (pending : Bool) (hPiop : RawDigest)
    (wire : DecodedMiddleWire) (decs : DecodedDecsResponseFields)
    (points : List Goldilocks) (salt binding : List Byte)
    (statementBinding : List Nat) (tapes : List (List Byte))
    (paths : List (List RawDigest)) (oracle : Oracle)
    (hashFpp : RawDigest) (finalPending : Bool)
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (executed : (pcsProgram ns pending hPiop wire decs points salt binding
      statementBinding tapes paths).eval oracle = some (hashFpp, finalPending)) :
    ∀ raw output,
      (raw, output) ∈ (recordedAttempt ns oracle stages.merkleInput).2 →
      (raw, output) ∈
        ((pcsProgram ns pending hPiop wire decs points salt binding
          statementBinding tapes paths).record oracle).2 := by
  let afterQuery : List Nat × Bool → Program (RawDigest × Bool) :=
    fun (indexes, sampledPending) =>
      match SmzaRp05DecsPointProjection.fieldPoints 406 indexes with
      | none => .done none
      | some decsPoints =>
          match SmzaRp05LvcsWireProjection.reconstructRowsFromPcsFields
              wire.pcs points decsPoints wire.rowScalars 64 widths deltas
              2 368 140 38 with
          | none => .done none
          | some rows =>
              if currentTwelveLvcsGate406 stages.heads
                  (wire.pcs.rcombiTails.map fieldWordsToGoldilocks)
                  points decsPoints rows then
                match SmzaRp05PcsMerklePayload.makeMerkleInput salt binding
                    sampledPending indexes rows decs.maskingEvals tapes paths with
                | none => .done none
                | some input =>
                    (postMerkleProgram ns input).bind fun post =>
                      match SmzaRp05DecsResponseProjection.hashFppProgram post.root decs
                          (rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
                          (SmzaRp05PcsHashFppMiddle.gammaRows post)
                          (decsPoints.map SmzaRp05ExecutableRestore.toWord)
                          140 368 statementBinding with
                      | none => .done none
                      | some hashProgram =>
                          match SmzaRp05DecsResponseProjection.restoredResponsePolynomials
                              decs
                              (rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
                              (SmzaRp05PcsHashFppMiddle.gammaRows post)
                              (decsPoints.map SmzaRp05ExecutableRestore.toWord)
                              140 368 with
                          | none => .done none
                          | some polynomials =>
                              if nativeFiveMcaGate406 salt tapes indexes
                                  (rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
                                  (SmzaRp05PcsHashFppMiddle.gammaRows post)
                                  decs.maskingEvals
                                  (decsPoints.map SmzaRp05ExecutableRestore.toWord)
                                  polynomials then
                                hashProgram.bind fun digest =>
                                  .done (some (digest, post.pending))
                              else .done none
              else .done none
  have programForm :
      pcsProgram ns pending hPiop wire decs points salt binding statementBinding
        tapes paths =
      (ask stages.openingInput).bind fun openingDigest =>
      (queryProgram pending openingDigest).bind afterQuery := by
    unfold pcsProgram
    rw [stages.headsBuilt]
    dsimp only
    rw [stages.openingBuilt]
    congr 1
  have opened := executed
  rw [programForm] at opened
  obtain ⟨openingDigest, openingRead, afterOpening⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (ask stages.openingInput) _ (hashFpp, finalPending) opened
  have openingEq : openingDigest = stages.openingDigest :=
    Option.some.inj (openingRead.symm.trans stages.openingRead)
  subst openingDigest
  obtain ⟨queryPair, queryRead, afterQueryEval⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (queryProgram pending stages.openingDigest) _ (hashFpp, finalPending) afterOpening
  have queryEq : queryPair = (stages.indexes, stages.sampledPending) :=
    Option.some.inj (queryRead.symm.trans stages.queryExecuted)
  subst queryPair
  have afterQuerySuccess :
      (afterQuery (stages.indexes, stages.sampledPending)).eval oracle =
        some (hashFpp, finalPending) := by
    simpa [afterQuery, stages.pointsBuilt, stages.rowsBuilt] using afterQueryEval
  have inputSuccess := afterQuerySuccess
  simp only [afterQuery, stages.pointsBuilt, stages.rowsBuilt] at inputSuccess
  cases lvcsGate : currentTwelveLvcsGate406 stages.heads
      (wire.pcs.rcombiTails.map fieldWordsToGoldilocks) points stages.decsPoints
      stages.rows with
  | false => simp [lvcsGate, Program.eval] at inputSuccess
  | true =>
      simp only [lvcsGate, stages.inputBuilt] at inputSuccess
      obtain ⟨post, postRead, afterPost⟩ :=
        SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
          (postMerkleProgram ns stages.merkleInput) _ (hashFpp, finalPending)
          inputSuccess
      have postEq : post = stages.post :=
        Option.some.inj (postRead.symm.trans stages.postExecuted)
      subst post
      have postLogIncluded :
          ((postMerkleProgram ns stages.merkleInput).record oracle).2 ⊆
            ((afterQuery (stages.indexes, stages.sampledPending)).record oracle).2 := by
        simpa [afterQuery, stages.pointsBuilt, stages.rowsBuilt, lvcsGate,
          stages.inputBuilt] using
          (Program.bind_log_left oracle (postMerkleProgram ns stages.merkleInput)
            (fun post =>
              match SmzaRp05DecsResponseProjection.hashFppProgram post.root decs
                  (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
                  (SmzaRp05PcsHashFppMiddle.gammaRows post)
                  (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord)
                  140 368 statementBinding with
              | none => .done none
              | some hashProgram =>
                  match SmzaRp05DecsResponseProjection.restoredResponsePolynomials decs
                      (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
                      (SmzaRp05PcsHashFppMiddle.gammaRows post)
                      (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord)
                      140 368 with
                  | none => .done none
                  | some polynomials =>
                      if nativeFiveMcaGate406 salt tapes stages.indexes
                          (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
                          (SmzaRp05PcsHashFppMiddle.gammaRows post)
                          decs.maskingEvals
                          (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord)
                          polynomials then
                        hashProgram.bind fun digest => .done (some (digest, post.pending))
                      else .done none)
            stages.post postRead)
      have coreAccepted :=
        SmzaRp05ExecutableChallengeStage.post_merkle_has_executed_core ns oracle
          stages.merkleInput stages.post stages.postExecuted
      have merkleLogIncluded :
          ((merkleProgram ns stages.merkleInput).record oracle).2 ⊆
            ((postMerkleProgram ns stages.merkleInput).record oracle).2 :=
        Program.bind_log_left oracle (merkleProgram ns stages.merkleInput)
          (afterMerkle stages.merkleInput) stages.post.root coreAccepted.1
      have attemptEq : (recordedAttempt ns oracle stages.merkleInput).2 =
          ((merkleProgram ns stages.merkleInput).record oracle).2 := by
        simp [recordedAttempt]
      have queryLogIncluded := Program.bind_log_right oracle
        (queryProgram pending stages.openingDigest) afterQuery
        (stages.indexes, stages.sampledPending) stages.queryExecuted
      have openingLogIncluded := Program.bind_log_right oracle
        (ask stages.openingInput)
        (fun openingDigest => (queryProgram pending openingDigest).bind afterQuery)
        stages.openingDigest stages.openingRead
      have totalSubset :
          ((merkleProgram ns stages.merkleInput).record oracle).2 ⊆
            (((ask stages.openingInput).bind fun openingDigest =>
              (queryProgram pending openingDigest).bind afterQuery).record oracle).2 := by
        intro call member
        exact openingLogIncluded
          (queryLogIncluded (postLogIncluded (merkleLogIncluded member)))
      intro raw output member
      have memberMerkle : (raw, output) ∈
          ((merkleProgram ns stages.merkleInput).record oracle).2 := by
        rw [← attemptEq]
        exact member
      have memberOpen : (raw, output) ∈
          (((ask stages.openingInput).bind fun openingDigest =>
            (queryProgram pending openingDigest).bind fun pair => afterQuery pair).record
              oracle).2 := by
        exact totalSubset memberMerkle
      rw [programForm]
      exact memberOpen

end

/-- Lift an accepted PCS subprogram's record into the same assembled
transcript/verifier execution. This is the source `bind` chronology; the
`ExecutionStages` equations supply the successful canonical-opening and PCS
binds, while `transcriptSuccess` supplies the verifier's accepted prefix. -/
theorem execution_pcs_records_retained_in_verifier
    (ns : Namespace) (dsl : SmzaRp05RelationRefinement.RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView)
    (oracle : Oracle) (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire oracle transcript)
    (transcriptSuccess :
      (transcriptProgram ns dsl statement pending statement.toBytes
        (statementBindingWords statement) nonce wire).eval
        oracle = some transcript) :
    ∀ call,
      call ∈ ((pcsProgram ns execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt statement.toBytes (statementBindingWords statement)
        wire.tapes wire.paths).record oracle).2 →
      call ∈ ((SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
        pending nonce wire).record oracle).2 := by
  let pcs := pcsProgram ns execution.openingPending wire.hPiop
    (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
    execution.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
    wire.salt statement.toBytes (statementBindingWords statement) wire.tapes wire.paths
  let matrixNext := fun pair : RawDigest × Bool =>
    (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement) pair.2 pair.1).bind
      fun (matrix, finalPending) =>
        .done (some (SmzaRp05ExecutableReconstruction.reconstruct dsl statement matrix
          execution.opening execution.piop pair.1 finalPending))
  have matrixInTranscript : (pcs.record oracle).2 ⊆
      ((pcs.bind matrixNext).record oracle).2 :=
    Program.bind_log_left oracle pcs matrixNext
      (execution.hashFpp, execution.pcsPending) execution.pcsExecuted
  let afterOpening : V8Smz9PiopSoundness.Opening × Bool →
      Program SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript :=
    fun openingPair =>
      let opening := openingPair.1
      let openingPending := openingPair.2
      (pcsProgram ns openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points opening j)
        wire.salt statement.toBytes (statementBindingWords statement)
        wire.tapes wire.paths).bind
        fun (hashFpp, pcsPending) =>
          (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
            pcsPending hashFpp).bind fun (matrix, finalPending) =>
              .done (some (SmzaRp05ExecutableReconstruction.reconstruct dsl statement
                matrix opening execution.piop hashFpp finalPending))
  have transcriptForm : transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire =
      (canonicalOpening pending nonce wire.hPiop).bind afterOpening := by
    simp only [transcriptProgram, execution.decoded, afterOpening]
  have pcsInTranscript : (pcs.record oracle).2 ⊆
      ((transcriptProgram ns dsl statement pending statement.toBytes
        (statementBindingWords statement) nonce wire).record oracle).2 := by
    rw [transcriptForm]
    intro call member
    have openingInTranscript : ((pcs.bind matrixNext).record oracle).2 ⊆
        (((canonicalOpening pending nonce wire.hPiop).bind afterOpening).record oracle).2 := by
      simpa [afterOpening, matrixNext, pcs] using
        (Program.bind_log_right oracle (canonicalOpening pending nonce wire.hPiop)
          afterOpening (execution.opening, execution.openingPending)
          execution.openingExecuted)
    exact openingInTranscript (matrixInTranscript member)
  have transcriptInVerifier := Program.bind_log_left oracle
    (transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire)
    (SmzaRp05ExecutableFinalVerifier.finalize wire.hPiop)
    transcript transcriptSuccess
  have pcsInVerifier : (pcs.record oracle).2 ⊆
      ((SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
        pending nonce wire).record oracle).2 := by
    intro call member
    exact transcriptInVerifier (pcsInTranscript member)
  intro call member
  have inVerifier := pcsInVerifier member
  simpa only [SmzaRp05ExecutablePcsClosureStatement.verifierProgram,
    SmzaRp05ExecutablePcsClosure.verifierProgram] using inVerifier

/-- A nonzero accepted physical branch of the combined producer/verifier
program supplies the very Merkle-record pairs used by its successful PCS
subexecution. The final containment is in that branch's `rawLog`, obtained
from `branch_record_eq_physical_rawLog`; this theorem does not take a
separately selected measured log or retention relation. -/
theorem accepted_physical_run_merkle_records_in_raw_log
    {Key Phase Work : Type}
    [Fintype Key] [DecidableEq Key]
    [Fintype RawDigest] [DecidableEq RawDigest] [AddCommGroup RawDigest]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Work] [DecidableEq Work]
    (encode : RawInput → Key) (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
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
          pending nonce wire) branch = some ()) :
    ∃ wire, ∃ transcript,
      ∃ execution : ExecutionStages ns dsl statement pending statement.toBytes
        (statementBindingWords statement) nonce wire
        (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
          basis fallback) transcript,
      ∃ pcs : PcsStages ns execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt statement.toBytes (statementBindingWords statement)
        wire.tapes wire.paths
        (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
          basis fallback)
        execution.hashFpp execution.pcsPending,
      producer.eval
          (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
            basis fallback) = some wire ∧
      (SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
        pending nonce wire).eval
          (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
            basis fallback) = some () ∧
      (SmzaRp05ExecutablePcsClosure.transcriptProgram ns dsl statement pending
        statement.toBytes (statementBindingWords statement) nonce wire).eval
          (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer) basis fallback) =
        some transcript ∧
      ∀ call,
        call ∈ (recordedAttempt
          ns (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
            basis fallback) pcs.merkleInput).2 →
        call ∈ rawLog (fun (_ : RawInput) (answer : RawDigest) => answer)
          (producer.bind fun wire =>
            SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
              pending nonce wire) branch := by
  let decode : RawInput → RawDigest → RawDigest :=
    fun (_ : RawInput) (answer : RawDigest) => answer
  let oracle := basisOracle encode decode basis fallback
  obtain ⟨wire, producerSuccess, verifierAccepted, rawSplit, _eventDichotomy⟩ :=
    SmzaRp05PhysicalProducerVerifierPrefix.accepted_physical_producer_prefix_dichotomy
      encode producer ns dsl statement pending nonce branch state basis fallback
      nonzero accepted
  obtain ⟨transcript, transcriptSuccess, _clean, _hashEq, _finalMember⟩ :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl
      statement pending statement.toBytes (statementBindingWords statement) nonce wire
      oracle verifierAccepted
  obtain ⟨execution⟩ :=
    SmzaRp05ExecutablePcsClosure.transcript_execution_has_stages ns dsl statement
      pending statement.toBytes (statementBindingWords statement) nonce wire oracle
      transcript transcriptSuccess
  obtain ⟨pcs⟩ :=
    SmzaRp05ExecutablePcsClosureStages.pcs_execution_has_stages ns
      execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement) wire.tapes
      wire.paths oracle execution.hashFpp execution.pcsPending execution.pcsExecuted
  have intoPcs := pcs_merkle_records_retained ns execution.openingPending wire.hPiop
    (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
    execution.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
    wire.salt statement.toBytes (statementBindingWords statement) wire.tapes wire.paths
    oracle execution.hashFpp execution.pcsPending pcs execution.pcsExecuted
  have intoVerifier := execution_pcs_records_retained_in_verifier ns dsl statement
    pending nonce wire oracle transcript execution transcriptSuccess
  refine ⟨wire, transcript, execution, pcs, producerSuccess, verifierAccepted,
    transcriptSuccess, ?_⟩
  intro call member
  have inPcs := intoPcs call.1 call.2 member
  have inVerifier := intoVerifier call inPcs
  change call ∈ rawLog (fun (_ : RawInput) (answer : RawDigest) => answer)
    (producer.bind fun wire =>
      SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
        pending nonce wire) branch
  rw [rawSplit]
  exact List.mem_append.mpr (Or.inr inVerifier)

end HegemonCrypto.SmallWood.SmzaRp05PhysicalPcsRecordRetention
