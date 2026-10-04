import SmzaRp05ExecutablePcsClosureDecsChecks
import SmzaRp05ExecutablePcsClosureLeafCodec

/-! Transport the native DECS dot product to the exact decoded leaf-cell
sum appearing in FiveMcaChecks. The source input row, mask words, and gamma
row remain explicit so the same-execution stage composition can supply them.
There is no independent leaf-value agreement premise. -/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureMcaAlgebra

open HegemonCrypto.CanonicalBytes
open SmzaRp05DecsResponseProjection
open SmzaRp05ExecutablePcsClosureDecsChecks
open SmzaRp05ExecutablePcsClosureAlgebra
open SmzaRp05ExecutablePcsClosureLeafCodec
open SmzaRp05ExecutableChallengeStage (FieldWord)
open SmzaRp05TracePrefixes (fieldWordAt)
open V8Smz9OracleExtraction (wordToGoldilocks)
open scoped BigOperators

set_option autoImplicit false
noncomputable section

private theorem foldl_add_eq_sum (indices : List Nat) (term : Nat → Goldilocks)
    (initial : Goldilocks) :
    indices.foldl (fun acc index => acc + term index) initial =
      initial + (indices.map term).sum := by
  induction indices generalizing initial with
  | nil => simp
  | cons head rest ih => simp [List.foldl_cons, ih, add_assoc]

theorem dec_evaluation_success_equation (row gamma : FieldRow)
    (mask result : Goldilocks) (success : decEvaluation row gamma mask = some result) :
    result = mask + ∑ index ∈ Finset.range gamma.length,
      gamma.getD index 0 * row.getD index 0 := by
  by_cases mismatch : row.length ≠ gamma.length
  · simp [decEvaluation, mismatch] at success
  · simp only [decEvaluation, if_neg mismatch] at success
    have outputEq := Option.some.inj success
    rw [← outputEq, foldl_add_eq_sum, zero_add,
      ← List.sum_toFinset _ List.nodup_range, List.toFinset_range, add_comm]
    congr 1
    apply Finset.sum_congr rfl
    intro index _
    exact mul_comm _ _

theorem normalized_data_goldilocks (salt tape : List Byte) (index : Nat)
    (row : FieldRow) (masks : List FieldWord)
    (saltLength : salt.length = 32) (tapeLength : tape.length = 64)
    (column : Nat) (bound : column < row.length) :
    wordToGoldilocks (fieldWordAt
      (SmzaRp05PcsMerklePayload.normalizedLeafPayload salt tape index row masks)
      (14 + column)) = row.getD column 0 := by
  unfold wordToGoldilocks
  rw [normalized_data_field salt tape index row masks saltLength tapeLength column bound]
  exact ZMod.natCast_zmod_val _

theorem normalized_mask_goldilocks (salt tape : List Byte) (index : Nat)
    (row : FieldRow) (masks : List FieldWord)
    (saltLength : salt.length = 32) (tapeLength : tape.length = 64)
    (rowLength : row.length = 140)
    (column : Nat) (bound : column < masks.length) :
    wordToGoldilocks (fieldWordAt
      (SmzaRp05PcsMerklePayload.normalizedLeafPayload salt tape index row masks)
      (155 + column)) = ((masks.getD column ⟨0, by decide⟩).val : Goldilocks) := by
  unfold wordToGoldilocks
  rw [normalized_mask_field salt tape index row masks saltLength tapeLength rowLength column bound]
  rfl

/-- The reconstructed row and transmitted masks satisfy the same decoded
leaf equation used by the existing acceptance predicate. -/
theorem successful_dec_evaluation_is_leaf_mca
    (salt tape : List Byte) (index : Nat) (row gamma : FieldRow)
    (masks : List FieldWord) (polynomial : Fin 5) (result : Goldilocks)
    (saltLength : salt.length = 32) (tapeLength : tape.length = 64)
    (rowLength : row.length = 140) (gammaLength : gamma.length = 140)
    (maskLength : masks.length = 5)
    (success : decEvaluation row gamma
      (masks.getD polynomial.val ⟨0, by decide⟩).val = some result) :
    let payload := SmzaRp05PcsMerklePayload.normalizedLeafPayload salt tape index row masks
    result = wordToGoldilocks (fieldWordAt payload (155 + polynomial.val)) +
      ∑ column : Fin 140, gamma.getD column.val 0 *
        wordToGoldilocks (fieldWordAt payload (14 + column.val)) := by
  dsimp only
  rw [normalized_mask_goldilocks salt tape index row masks saltLength tapeLength
    rowLength polynomial.val (by omega)]
  have data := fun column : Fin 140 => normalized_data_goldilocks salt tape index
    row masks saltLength tapeLength column.val (by omega)
  simp_rw [data]
  have sumEq :
    (∑ column : Fin 140,
        gamma.getD column.val 0 * row.getD column.val 0) =
        ∑ index ∈ Finset.range gamma.length,
          gamma.getD index 0 * row.getD index 0 := by
    rw [gammaLength]
    let term : Fin 140 → Goldilocks := fun column =>
      gamma.getD column.val 0 * row.getD column.val 0
    change (∑ column : Fin 140, term column) =
      ∑ index ∈ Finset.range 140, gamma.getD index 0 * row.getD index 0
    rw [← Fin.sum_univ_eq_sum_range]
  have decoded := dec_evaluation_success_equation row gamma
    (masks.getD polynomial.val ⟨0, by decide⟩).val result success
  rw [sumEq]
  exact decoded

private theorem masking_map_getD (rows : List (List FieldWord))
    (evaluationIndex polynomialIndex : Nat) :
    ((rows.map fun row =>
      ((row.getD polynomialIndex ⟨0, by decide⟩).val : Goldilocks)).getD
      evaluationIndex 0) =
        ((rows.getD evaluationIndex []).getD polynomialIndex ⟨0, by decide⟩).val := by
  induction rows generalizing evaluationIndex with
  | nil => cases evaluationIndex <;> rfl
  | cons head tail ih =>
      cases evaluationIndex with
      | zero => rfl
      | succ index => exact ih index

/-- Compose native restoration with the exact normalized leaf codec. For
each of the five restored rows and 38 opening positions, the restored
polynomial evaluates to the MCA expression over the calculated LVCS row and
the transmitted mask row. This is an algebraic source-output fact, not a
claim that the mathematical final verifier executes an independent MCA gate. -/
theorem successful_restore_has_five_leaf_mca
    (fields : DecodedDecsResponseFields)
    (lvcsRows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (rowCount highCount : Nat) (polynomials : List FieldRow)
    (success : restoredResponsePolynomials fields lvcsRows gamma evalPoints
      rowCount highCount = some polynomials)
    (salt : List Byte) (tapes : List (List Byte)) (leafIndexes : List Nat)
    (saltLength : salt.length = 32)
    (tapeLength : ∀ index, index < 38 → (tapes.getD index []).length = 64)
    (rowShape : ∀ index, index < 38 →
      (decodeFieldRow (lvcsRows.getD index [])).length = 140)
    (gammaShape : ∀ polynomialIndex, polynomialIndex < 5 →
      (decodeFieldRow (gamma.getD polynomialIndex [])).length = 140)
    (maskShape : ∀ index, index < 38 →
      (fields.maskingEvals.getD index []).length = 5) :
    ∀ polynomialIndex, polynomialIndex < 5 →
      ∀ evaluationIndex, evaluationIndex < 38 →
        (coefficientPolynomial (polynomials.getD polynomialIndex [])).eval
            ((decodeFieldRow evalPoints).getD evaluationIndex 0) =
          wordToGoldilocks (fieldWordAt
            (SmzaRp05PcsMerklePayload.normalizedLeafPayload salt
              (tapes.getD evaluationIndex []) (leafIndexes.getD evaluationIndex 0)
              (decodeFieldRow (lvcsRows.getD evaluationIndex []))
              (fields.maskingEvals.getD evaluationIndex []))
            (155 + polynomialIndex)) +
          ∑ column : Fin 140,
            (decodeFieldRow (gamma.getD polynomialIndex [])).getD column.val 0 *
              wordToGoldilocks (fieldWordAt
                (SmzaRp05PcsMerklePayload.normalizedLeafPayload salt
                  (tapes.getD evaluationIndex []) (leafIndexes.getD evaluationIndex 0)
                  (decodeFieldRow (lvcsRows.getD evaluationIndex []))
                  (fields.maskingEvals.getD evaluationIndex []))
                (14 + column.val)) := by
  obtain ⟨pointsLength, pointsDistinct, polynomialCount, branches⟩ :=
    restored_response_exposes_branches fields lvcsRows gamma evalPoints
      rowCount highCount polynomials success
  intro polynomialIndex polynomialBound evaluationIndex evaluationBound
  have branch := branches polynomialIndex polynomialBound
  unfold sourceRestore at branch
  cases valuesEq : (List.range 38).mapM
      (sourceEvaluation fields lvcsRows gamma polynomialIndex) with
  | none => simp [valuesEq] at branch
  | some values =>
      simp only [valuesEq] at branch
      have sourceCheck := successful_response_has_five_source_checks fields
        lvcsRows gamma evalPoints rowCount highCount polynomials success
      have equation := sourceCheck.2 polynomialIndex polynomialBound
        evaluationIndex evaluationBound
      cases sourceValue : sourceEvaluation fields lvcsRows gamma
          polynomialIndex evaluationIndex with
      | none => simp [sourceValue] at equation
      | some value =>
          have sourceSuccess : decEvaluation
              (decodeFieldRow (lvcsRows.getD evaluationIndex []))
            (decodeFieldRow (gamma.getD polynomialIndex []))
              ((fields.maskingEvals.getD evaluationIndex []).getD polynomialIndex
                ⟨0, by decide⟩).val = some value := by
            change decEvaluation
              (decodeFieldRow (lvcsRows.getD evaluationIndex []))
              (decodeFieldRow (gamma.getD polynomialIndex []))
              (((fields.maskingEvals.map fun row =>
                ((row.getD polynomialIndex ⟨0, by decide⟩).val : Goldilocks)).getD evaluationIndex 0)) =
                some value at sourceValue
            rw [masking_map_getD] at sourceValue
            exact sourceValue
          have leafEquation := successful_dec_evaluation_is_leaf_mca salt
            (tapes.getD evaluationIndex []) (leafIndexes.getD evaluationIndex 0)
            (decodeFieldRow (lvcsRows.getD evaluationIndex []))
            (decodeFieldRow (gamma.getD polynomialIndex []))
            (fields.maskingEvals.getD evaluationIndex []) ⟨polynomialIndex,
              by omega⟩ value saltLength (tapeLength evaluationIndex evaluationBound)
            (rowShape evaluationIndex evaluationBound)
            (gammaShape polynomialIndex polynomialBound)
            (maskShape evaluationIndex evaluationBound) sourceSuccess
          have valueEquation : value =
              (coefficientPolynomial (polynomials.getD polynomialIndex [])).eval
                ((decodeFieldRow evalPoints).getD evaluationIndex 0) :=
            Option.some.inj (sourceValue.symm.trans equation)
          rw [valueEquation.symm]
          exact leafEquation

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureMcaAlgebra
