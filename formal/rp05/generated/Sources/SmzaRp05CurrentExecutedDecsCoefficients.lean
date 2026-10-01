import SmzaRp05CurrentExecutedMatrixReadback
import SmzaRp05CurrentAcceptedQuerySupport
import SmzaRp05PcsHashFppMiddle
import SmzaRp05CurrentDecsMatrixSampling

/-! Same-run coefficient interpretation of the actual post-Merkle DECS
sampler. Clean pending is used only to derive sampler success; no sampled
matrix or successful-output premise is added. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedDecsCoefficients

open SmzaRp05ExecutableChallengeStage (PostMerkle FieldWord)
open SmzaRp05ExecutableChallengeStage (scan counterKeys)
open SmzaRp05ExecutableMerkleVerifier (Oracle)
open SmzaRp05CurrentDecsMatrixSampling
  (currentDecsMatrixFieldEquiv currentActualDecsMatrixOutput)
open V8Smz9CappedRawSampler (FieldOutput sourceFieldSize)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)
open V8Smz9RawCounterCompiler (digestCallCap)
open V8SmzaOracleParser (RawDigest)
open SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients)
open SmzaRp05PcsHashFppMiddle (gammaRows)
open V8Smz9RuntimeFieldLayout (matrixEquiv)
open V8Smz9RuntimeRandomness (idealFieldCoinEquivGoldilocks)
open SmzaRp05DecsResponseProjection (decodeFieldRow)

set_option autoImplicit false
noncomputable section

private def wordsAsOutput (words : List FieldWord) :
    FieldOutput sourceFieldSize (140 * 5) :=
  fun index => words.getD index.val SmzaRp05ExecutableChallengeStage.zeroWord

private theorem fin_equiv_nat_cast (n : Nat) [NeZero n] (word : Fin n) :
    (ZMod.finEquiv n) word = (word.val : ZMod n) := by
  cases n with
  | zero => exact (NeZero.ne 0 rfl).elim
  | succ n =>
    apply ZMod.val_injective
    change word.val = ((word.val : ZMod (n + 1)).val)
    simp [ZMod.val_natCast, Nat.mod_eq_of_lt word.isLt]

private theorem ideal_field_coin_apply (word : FieldWord) :
    idealFieldCoinEquivGoldilocks word = word.val := by
  letI : NeZero V8Smz9RuntimeRandomness.fieldModulus := ⟨by decide⟩
  change (ZMod.finEquiv V8Smz9RuntimeRandomness.fieldModulus) word =
    (word.val : ZMod V8Smz9RuntimeRandomness.fieldModulus)
  exact fin_equiv_nat_cast V8Smz9RuntimeRandomness.fieldModulus word

private theorem current_decs_words_decode_as_gamma (post : PostMerkle)
    (words : List FieldWord) (sampledEq : post.sampled = some words) :
    currentDecsMatrixFieldEquiv (wordsAsOutput words) =
      sampledCoefficients (gammaRows post) := by
  funext column row
  calc
    currentDecsMatrixFieldEquiv (wordsAsOutput words) column row =
        idealFieldCoinEquivGoldilocks
          (wordsAsOutput words
            ((finProdFinEquiv : Fin 5 × Fin 140 ≃ Fin (5 * 140)) (row, column))) :=
      SmzaRp05CurrentDecsMatrixSampling.current_decs_matrix_field_equiv_apply
        (wordsAsOutput words) column row
    _ = sampledCoefficients (gammaRows post) column row := by
      rw [ideal_field_coin_apply]
      simp [SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients,
        SmzaRp05PcsHashFppMiddle.gammaRows,
        SmzaRp05ExecutableChallengeStage.returnedWords,
        SmzaRp05DecsResponseProjection.decodeFieldRow,
        wordsAsOutput, sampledEq, finProdFinEquiv,
        List.getD_eq_getElem?_getD]
      have sameIndex : column.val + 140 * row.val =
          row.val * 140 + column.val := by omega
      rw [sameIndex]
      cases h : words[row.val * 140 + column.val]? <;>
        simp [SmzaRp05ExecutableChallengeStage.zeroWord]

/-- A successful post-Merkle run whose actual pending bit is clear has a
successful literal 700-word matrix sample, and the raw-role decoder output is
exactly the 5-by-140 DECS coefficient matrix assembled by the verifier. -/
theorem executed_clean_post_merkle_actual_decs_coefficients
    (ns : SmzaRp05LeafNamespace.Namespace) (oracle : Oracle)
    (input : SmzaRp05ExecutableMerkleVerifier.Input) (post : PostMerkle)
    (executed : (SmzaRp05ExecutableChallengeStage.postMerkleProgram ns input).eval oracle = some post)
    (clean : post.pending = false) :
    currentActualDecsMatrixOutput
      (Equiv.refl (Fin (digestCallCap (140 * 5))))
      (HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedMatrixReadback.currentDecsMatrixVector
        oracle post.root) =
      some (sampledCoefficients (gammaRows post)) := by
  obtain ⟨_, sampledEq, pendingEq, _⟩ :=
    SmzaRp05ExecutableChallengeStage.post_merkle_has_executed_core
      ns oracle input post executed
  have failure : SmzaRp05ExecutableChallengeStage.pendingFailure
      input.pendingXofFailure post.sampled = false := by
    rw [← pendingEq]
    exact clean
  obtain ⟨_, words, wordsEq⟩ :=
    SmzaRp05ExecutableChallengeStage.finished_xof_has_exact_words
      input.pendingXofFailure post.sampled failure
  have sampledRun : scan oracle 700 []
      (SmzaRp05ExecutableChallengeStage.counterKeys
        HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain 700 post.root) = some words := by
    rw [← wordsEq]
    exact sampledEq.symm
  have lengthEq := SmzaRp05ExecutableChallengeStage.scan_success_length
    oracle 700 []
    (SmzaRp05ExecutableChallengeStage.counterKeys
      HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain 700 post.root)
    words sampledRun
  have rawEq :=
    SmzaRp05CurrentExecutedMatrixReadback.executed_post_merkle_actual_decs_matrix_raw_output
      ns oracle input post executed
  simp only [wordsEq, Option.bind_some,
    SmzaRp04RawRoleSampling.totalEquivDecoder] at rawEq
  change currentActualDecsMatrixOutput
      (Equiv.refl (Fin (digestCallCap (140 * 5))))
      (HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedMatrixReadback.currentDecsMatrixVector
        oracle post.root) =
    some (currentDecsMatrixFieldEquiv (wordsAsOutput words)) at rawEq
  rw [current_decs_words_decode_as_gamma post words wordsEq] at rawEq
  exact rawEq

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedDecsCoefficients
