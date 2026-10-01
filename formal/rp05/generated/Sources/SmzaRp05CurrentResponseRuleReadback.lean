import SmzaRp05CurrentResponsePrequeryDecode
import SmzaRp05CurrentMaxAgreementRecovery

/-! # Bounded current response rows from a selected transcript

This module turns an explicitly selected raw input and its decoded 5×406
response rows into the response type used by current maximum-agreement
recovery. The selection may depend on the matrix challenge; it is therefore
not described as a pre-challenge fixed response rule. Chronology remains an
upstream obligation.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentResponseRuleReadback

set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 600000
noncomputable section

abbrev Goldilocks := HegemonCrypto.SmallWood.Goldilocks
abbrev FieldRow := SmzaRp05DecsResponseProjection.FieldRow
abbrev Coefficients := SmzaRp05CurrentMaxAgreementRecovery.Coefficients
abbrev ResponseRule := SmzaRp05CurrentMaxAgreementRecovery.ResponseRule
abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev BoundedResponse (F Row : Type*) [Field F] (degree : Nat) :=
  HegemonCrypto.SmallWood.V8Smz9McaRecovery.BoundedResponse F Row degree
abbrev coefficientPolynomial :=
  SmzaRp05ExecutablePcsClosureAlgebra.coefficientPolynomial

/-- Encode the actual finite 406 coefficients of each restored row into the
degree-405 finite response type. The degree bound is structural: the type is
constructed by the inverse of `degreeLTEquiv`. -/
def boundedResponseOfRows (rows : List FieldRow) :
    BoundedResponse Goldilocks (Fin 5) 405 :=
  fun row => (Polynomial.degreeLTEquiv Goldilocks 406).symm
    (fun coefficient => (rows.getD row.val []).getD coefficient.val 0)

/-- Coefficient readback for the finite-dimensional encoding. This is stated
for the source's 406-cell row shape, not a 388/387 truncation. -/
theorem bounded_response_of_rows_readback (rows : List FieldRow)
    (row : Fin 5) (rowLength : (rows.getD row.val []).length = 406) :
    HegemonCrypto.SmallWood.V8Smz9McaRecovery.responsePolynomials
        (boundedResponseOfRows rows) row =
      coefficientPolynomial (rows.getD row.val []) := by
  change (boundedResponseOfRows rows row).val =
    coefficientPolynomial (rows.getD row.val [])
  apply Polynomial.ext
  intro degree
  by_cases bound : degree < 406
  · let index : Fin 406 := ⟨degree, bound⟩
    let coefficient : Fin 406 → Goldilocks :=
      fun entry => (rows.getD row.val []).getD entry.val 0
    have encoded := congrFun
      ((Polynomial.degreeLTEquiv Goldilocks 406).apply_symm_apply
        coefficient) index
    have encoded' : ((boundedResponseOfRows rows row).val).coeff degree =
        (rows.getD row.val []).getD degree 0 := by
      change ((Polynomial.degreeLTEquiv Goldilocks 406).symm coefficient).val.coeff
        index.val = coefficient index at encoded
      have indexValue : index.val = degree := rfl
      rw [indexValue] at encoded
      simpa only [boundedResponseOfRows, coefficient, index] using encoded
    rw [SmzaRp05ExecutablePcsClosureAlgebra.coefficient_polynomial_coeff]
    exact encoded'
  · have beyond : (rows.getD row.val []).getD degree 0 = 0 := by
      have absent : (rows.getD row.val [])[degree]? = none :=
        List.getElem?_eq_none (by rw [rowLength]; omega)
      change ((rows.getD row.val [])[degree]?).getD 0 = 0
      rw [absent]
      rfl
    rw [SmzaRp05ExecutablePcsClosureAlgebra.coefficient_polynomial_coeff, beyond]
    have encodedZero : ((boundedResponseOfRows rows row).val).coeff degree = 0 := by
      have degreeBound := HegemonCrypto.SmallWood.V8Smz9McaRecovery.bounded_response_degree
        (boundedResponseOfRows rows) row
      change (boundedResponseOfRows rows row).val.natDegree ≤ 405 at degreeBound
      exact Polynomial.coeff_eq_zero_of_natDegree_lt (by omega)
    exact encodedZero

/-- Select a decoded restored-row table at each matrix challenge. The raw input
selection is explicit and can be tied to the retained-preimage branch by a
caller; this definition does not claim the selected input is independent of
the challenge. -/
def responseRuleOfInputSelection
    (selectInput : Coefficients → RawInput)
    (decodeRows : RawInput → List FieldRow) :
    ResponseRule :=
  fun coefficients => boundedResponseOfRows (decodeRows (selectInput coefficients))

/-- The selected rule reads back exactly the decoded rows at every matrix. -/
theorem response_rule_of_input_selection_readback
    (selectInput : Coefficients → RawInput)
    (decodeRows : RawInput → List FieldRow)
    (rowLength : ∀ (coefficients : Coefficients) (row : Fin 5),
      ((decodeRows (selectInput coefficients)).getD row.val []).length = 406)
    (coefficients : Coefficients) (row : Fin 5) :
    HegemonCrypto.SmallWood.V8Smz9McaRecovery.responsePolynomials
      (responseRuleOfInputSelection selectInput decodeRows
      coefficients) row =
        coefficientPolynomial ((decodeRows (selectInput coefficients)).getD row.val []) :=
  bounded_response_of_rows_readback (decodeRows (selectInput coefficients)) row
    (rowLength coefficients row)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentResponseRuleReadback
