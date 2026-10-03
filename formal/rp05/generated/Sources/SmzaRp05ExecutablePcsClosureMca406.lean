import SmzaRp05ExecutablePcsClosureMcaAlgebra

/-! The current RP05 DECS source emits 38 opened coefficients plus 368
proof-carried high coefficients. This source predicate keeps that full 406-term
polynomial; it does not squeeze it into the older degree-387 response type. -/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureMca406

open HegemonCrypto.CanonicalBytes
open SmzaRp05DecsResponseProjection
open SmzaRp05ExecutablePcsClosureDecsChecks
open SmzaRp05ExecutablePcsClosureMcaAlgebra
open SmzaRp05ExecutablePcsClosureAlgebra
open SmzaRp05ExecutableChallengeStage (FieldWord)
open SmzaRp05TracePrefixes (fieldWordAt)
open V8Smz9OracleExtraction (wordToGoldilocks)
open scoped BigOperators

set_option autoImplicit false
noncomputable section

/-- Exact current-profile five-row MCA equations over the complete
38+368-coefficient restoration output and its normalized committed leaf. -/
def NativeFiveMcaChecks406
    (salt : List Byte) (tapes : List (List Byte)) (leafIndexes : List Nat)
    (rows gamma masks : List (List FieldWord))
    (evalPoints : List FieldWord) (polynomials : List FieldRow) : Prop :=
  ∀ polynomialIndex, polynomialIndex < 5 →
    ∀ evaluationIndex, evaluationIndex < 38 →
      (coefficientPolynomial (polynomials.getD polynomialIndex [])).eval
          ((decodeFieldRow evalPoints).getD evaluationIndex 0) =
        wordToGoldilocks (fieldWordAt
          (SmzaRp05PcsMerklePayload.normalizedLeafPayload salt
            (tapes.getD evaluationIndex []) (leafIndexes.getD evaluationIndex 0)
            (decodeFieldRow (rows.getD evaluationIndex []))
            (masks.getD evaluationIndex []))
          (155 + polynomialIndex)) +
        ∑ column : Fin 140,
          (decodeFieldRow (gamma.getD polynomialIndex [])).getD column.val 0 *
            wordToGoldilocks (fieldWordAt
              (SmzaRp05PcsMerklePayload.normalizedLeafPayload salt
                (tapes.getD evaluationIndex []) (leafIndexes.getD evaluationIndex 0)
                (decodeFieldRow (rows.getD evaluationIndex []))
                (masks.getD evaluationIndex []))
              (14 + column.val))

theorem successful_restore_rows_have_406_coefficients
    (fields : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (polynomials : List FieldRow)
    (success : restoredResponsePolynomials fields rows gamma evalPoints 140 368 =
      some polynomials) :
    polynomials.length = 5 ∧
      ∀ polynomialIndex, polynomialIndex < 5 →
        (polynomials.getD polynomialIndex []).length = 406 := by
  obtain ⟨pointLength, _pointNodup, polynomialCount, branches⟩ :=
    restored_response_exposes_branches fields rows gamma evalPoints 140 368
      polynomials success
  have shapes := restored_response_shape_facts fields rows gamma evalPoints
    140 368 polynomials success
  refine ⟨polynomialCount, ?_⟩
  intro polynomialIndex polynomialBound
  have branch := branches polynomialIndex polynomialBound
  unfold sourceRestore at branch
  cases valuesBuilt : (List.range 38).mapM
      (sourceEvaluation fields rows gamma polynomialIndex) with
  | none => simp [valuesBuilt] at branch
  | some values =>
      simp only [valuesBuilt] at branch
      have highIndexBound : polynomialIndex < fields.highCoeffs.length := by
        rw [shapes.1]
        omega
      have highMember : fields.highCoeffs.getD polynomialIndex [] ∈ fields.highCoeffs := by
        rw [List.getD_eq_getElem fields.highCoeffs [] highIndexBound]
        exact List.getElem_mem highIndexBound
      have highLength : (decodeFieldRow
          (fields.highCoeffs.getD polynomialIndex [])).length = 368 := by
        simpa [decodeFieldRow] using shapes.2.2.2.2.2.2.2.2
          (fields.highCoeffs.getD polynomialIndex []) highMember
      have pointsLength : (decodeFieldRow evalPoints).length = 38 := by
        simpa [decodeFieldRow] using pointLength
      have emitted := successful_restore_emits_expression
        (decodeFieldRow evalPoints) values
        (decodeFieldRow (fields.highCoeffs.getD polynomialIndex []))
        (polynomials.getD polynomialIndex []) branch
      rw [emitted.2]
      simp only [List.length_map, List.length_range]
      rw [pointsLength, highLength]

/-- The accepted source-shaped restoration calculation itself proves all five
current-profile equations. The polynomial is the native 406-coefficient
output, not an assumed `BoundedResponse ... 387`. -/
theorem successful_restore_has_native_five_mca_406
    (fields : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (polynomials : List FieldRow)
    (success : restoredResponsePolynomials fields rows gamma evalPoints 140 368 =
      some polynomials)
    (salt : List Byte) (tapes : List (List Byte)) (leafIndexes : List Nat)
    (saltLength : salt.length = 32)
    (tapeLength : ∀ index, index < 38 → (tapes.getD index []).length = 64)
    (rowShape : ∀ index, index < 38 →
      (decodeFieldRow (rows.getD index [])).length = 140)
    (gammaShape : ∀ polynomialIndex, polynomialIndex < 5 →
      (decodeFieldRow (gamma.getD polynomialIndex [])).length = 140)
    (maskShape : ∀ index, index < 38 →
      (fields.maskingEvals.getD index []).length = 5) :
    (∀ polynomialIndex, polynomialIndex < 5 →
      (polynomials.getD polynomialIndex []).length = 406) ∧
      NativeFiveMcaChecks406 salt tapes leafIndexes rows gamma
        fields.maskingEvals evalPoints polynomials := by
  have fullLength := successful_restore_rows_have_406_coefficients fields
    rows gamma evalPoints polynomials success
  refine ⟨fullLength.2, ?_⟩
  intro polynomialIndex polynomialBound evaluationIndex evaluationBound
  have sourceEquation := successful_restore_has_five_leaf_mca
    fields rows gamma evalPoints 140 368 polynomials success salt tapes leafIndexes
    saltLength tapeLength rowShape gammaShape maskShape
    polynomialIndex polynomialBound evaluationIndex evaluationBound
  exact sourceEquation

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureMca406
