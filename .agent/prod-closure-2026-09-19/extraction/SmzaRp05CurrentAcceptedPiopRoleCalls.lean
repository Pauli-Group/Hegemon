import SmzaRp05CurrentPrequeryChronology
import SmzaRp05ExecutablePcsClosureSampling

/-! # Same-run PIOP raw role calls

Expose an actual counter-zero PIOP-matrix call from the exact successful
matrix sampler and transcript record. This is the raw-log half of the grouped
answer-log bridge; it does not posit a grouped answer or vector.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopRoleCalls

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutableChallengeStage (counterInput counterKeys fieldLoop fieldXof)
open SmzaRp05ExecutablePcsClosure (ExecutionStages transcriptProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05CurrentPrequeryChronology (transcript_q38_record_split afterQ38)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05ExecutableChallengeStage (scan)
open V8SmzaOracleParser (RawDigest RawInput)
open HegemonCrypto.CanonicalBytes (Byte)

set_option autoImplicit false
set_option maxHeartbeats 1000000

private theorem counter_keys_cons (requested : Nat) (positive : 0 < requested)
    (digest : RawDigest) :
    counterKeys HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain requested digest =
      counterInput HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain digest 0 ::
        (counterKeys HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain
          requested digest).tail := by
  unfold counterKeys
  have capPositive : 0 < SmzaRp05ExecutableChallengeStage.callCap requested := by
    simp only [SmzaRp05ExecutableChallengeStage.callCap]
    split <;> omega
  cases cap : SmzaRp05ExecutableChallengeStage.callCap requested with
  | zero => omega
  | succ n =>
      change List.map
        (counterInput HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain digest)
          (List.range (n + 1)) = _
      rw [List.range_succ_eq_map]
      simp only [List.map_cons, List.tail_cons]

private theorem first_counter_recorded_in_matrix_sampler
    (width : Nat) (pending : Bool) (positive : 0 < width) (digest : RawDigest)
    (oracle : Oracle) (words : List SmzaRp05ExecutableChallengeStage.FieldWord)
    (succeeded : scan oracle (5 * width) []
      (counterKeys HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain
        (5 * width) digest) = some words) :
    (counterInput HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain digest 0,
      oracle (counterInput HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain digest 0)) ∈
      ((SmzaRp05PiopMatrixStage.matrixProgram width pending digest).record oracle).2 := by
  have requestedPositive : 0 < 5 * width := by omega
  have keys := counter_keys_cons (5 * width) requestedPositive digest
  have fieldEval :
      (fieldLoop (5 * width) []
        (counterKeys HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain
          (5 * width) digest)).eval oracle = some (some words) := by
    rw [SmzaRp05ExecutableChallengeStage.field_loop_executes_scan, succeeded]
  have headRecord :
      (counterInput HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain digest 0,
        oracle (counterInput HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain digest 0)) ∈
      ((fieldLoop (5 * width) []
        (counterKeys HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain
          (5 * width) digest)).record oracle).2 := by
    rw [keys]
    have notDone : ¬ (5 * width ≤ 0) := by omega
    simp only [fieldLoop, List.length_nil]
    rw [if_neg notDone]
    simp only [Program.record]
    exact List.mem_cons_self
  have xofRecord := Program.bind_log_left oracle
    (fieldXof HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain (5 * width) digest)
      (fun sampled => .done (some (SmzaRp05PiopMatrixStage.matrixFromWords width
      (SmzaRp05ExecutableChallengeStage.returnedWords (5 * width) sampled),
      SmzaRp05ExecutableChallengeStage.pendingFailure pending sampled)))
    (some words) (by simpa [fieldXof] using fieldEval) headRecord
  simpa [SmzaRp05PiopMatrixStage.matrixProgram, fieldXof] using xofRecord

/-- The matrix counter-zero call is in the *same transcript* record. The
sampler suffix is taken from the exact successful stages, not supplied as an
independent execution. -/
theorem execution_matrix_counter_zero_raw_call
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
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
    (widthPositive : 0 < dsl.width statement)
    (clean : execution.finalPending = false) :
    (counterInput HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain
      execution.hashFpp 0,
      oracle (counterInput HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain
        execution.hashFpp 0)) ∈
      ((transcriptProgram ns dsl statement pending statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire).record oracle).2 := by
  obtain ⟨_, words, sampled, _⟩ :=
    SmzaRp05ExecutablePcsClosureSampling.matrix_execution_clean
      (dsl.width statement) execution.pcsPending execution.hashFpp oracle
      execution.matrix execution.finalPending execution.matrixExecuted clean
  have inMatrix := first_counter_recorded_in_matrix_sampler
    (dsl.width statement) execution.pcsPending widthPositive execution.hashFpp
    oracle words sampled
  have split := transcript_q38_record_split ns dsl statement pending nonce wire
    oracle transcript execution pcs
  rw [split]
  simp only [List.mem_append]
  exact Or.inr inMatrix

end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopRoleCalls
