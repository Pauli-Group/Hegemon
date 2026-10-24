import HegemonCrypto.NativeLaunchWireTypes
import SmzaRp05ExecutablePcsClosureAlgebra
import HegemonCrypto.NativeHtlcUniversalMatrix

/-!
# Native launch branch geometry and calculated DECS response

This model uses the generic literal `poly_restore` algebra, not the old
q38/406 response wrapper. Every branch retains its own source geometry.
Coordinates come from typed wire fields. Raw parsing, Merkle readback,
FPP precommitment binding, and challenge chronology remain external obligations.
No probability or security-bit bound is asserted.
-/
namespace HegemonCrypto.SmallWood.NativeLaunchRelationModelResponse

open Polynomial
open scoped BigOperators
open SmzaRp05ExecutableRestore SmzaRp05DecsResponseProjection
open SmzaRp05ExecutablePcsClosureAlgebra
open V8Smz9McaRecovery V8Smz9McaDecoder NativeHtlcUniversalMatrix

set_option autoImplicit false
noncomputable section

def highCount : Branch → Nat
  | .rp06 => 368
  | .htlcClaim => 9876
  | _ => 2062

def degree : Branch → Nat
  | .rp06 => 405
  | .htlcClaim => 9933
  | _ => 2119

theorem branch_coefficient_count (branch : Branch) :
    queryCount branch + highCount branch = degree branch + 1 := by
  cases branch <;> decide

abbrev MaskRow := Fin 5
abbrev Column := Fin 140
abbrev Matrix := Column → MaskRow → Goldilocks

/-- Exact typed DECS fields after canonical field decoding and dimension checks.
The source-provided high coefficients begin at degree `queryCount branch`. -/
structure WireFields (branch : Branch) (Position : Type*) where
  positions : Fin (queryCount branch) → Position
  high : MaskRow → Fin (highCount branch) → Goldilocks
  sourceCells : Fin (queryCount branch) → Column → Goldilocks
  maskingEvals : Fin (queryCount branch) → MaskRow → Goldilocks

def points {branch : Branch} {Position : Type*}
    (point : Position → Goldilocks) (wire : WireFields branch Position) : FieldRow :=
  List.ofFn fun index => point (wire.positions index)

def values {branch : Branch} {Position : Type*}
    (wire : WireFields branch Position) (matrix : Matrix) (row : MaskRow) : FieldRow :=
  List.ofFn fun index =>
    (∑ column : Column, wire.sourceCells index column * matrix column row) +
      wire.maskingEvals index row

def highWords {branch : Branch} {Position : Type*}
    (wire : WireFields branch Position) (row : MaskRow) : FieldRow :=
  List.ofFn (wire.high row)

/-- The coefficient list actually calculated by the generic source restoration.
There is no supplied response polynomial or evaluation-correctness certificate. -/
def restoredWords {branch : Branch} {Position : Type*}
    (point : Position → Goldilocks) (wire : WireFields branch Position)
    (matrix : Matrix) (row : MaskRow) : FieldRow :=
  (List.range (queryCount branch + highCount branch)).map fun index =>
    coefficient (restoredExpression (points point wire) (values wire matrix row)
      (highWords wire row)) index

theorem restoration_returns_calculated_words {branch : Branch} {Position : Type*}
    (point : Position → Goldilocks) (wire : WireFields branch Position)
    (matrix : Matrix) (row : MaskRow) :
    polyRestoreResponse (points point wire) (values wire matrix row)
      (highWords wire row) = some (restoredWords point wire matrix row) := by
  simp [polyRestoreResponse, points, values, highWords, restoredWords,
    restoredExpression]

theorem restored_words_length {branch : Branch} {Position : Type*}
    (point : Position → Goldilocks) (wire : WireFields branch Position)
    (matrix : Matrix) (row : MaskRow) :
    (restoredWords point wire matrix row).length = degree branch + 1 := by
  simp [restoredWords, branch_coefficient_count]

theorem calculated_polynomial_degree {branch : Branch} {Position : Type*}
    (point : Position → Goldilocks) (wire : WireFields branch Position)
    (matrix : Matrix) (row : MaskRow) :
    coefficientPolynomial (restoredWords point wire matrix row) ∈
      Polynomial.degreeLT Goldilocks (degree branch + 1) := by
  apply Polynomial.mem_degreeLT.mpr
  rw [Polynomial.degree_lt_iff_coeff_zero]
  intro index above
  rw [coefficient_polynomial_coeff]
  have beyond : ¬ index < (restoredWords point wire matrix row).length := by
    rw [restored_words_length]
    omega
  simp [List.getD_eq_getElem?_getD, beyond]

def calculatedResponse {branch : Branch} {Position : Type*}
    (point : Position → Goldilocks) (wire : WireFields branch Position)
    (matrix : Matrix) : BoundedResponse Goldilocks MaskRow (degree branch) :=
  fun row => ⟨coefficientPolynomial (restoredWords point wire matrix row),
    calculated_polynomial_degree point wire matrix row⟩

theorem getD_ofFn_at {count : Nat} (f : Fin count → Goldilocks) (index : Fin count) :
    (List.ofFn f).getD index.val 0 = f index := by
  simp [List.getD_eq_getElem?_getD]

theorem typed_point_injection_implies_restore_distinct
    {branch : Branch} {Position : Type*}
    (point : Position → Goldilocks) (wire : WireFields branch Position)
    (distinct : Function.Injective (fun index => point (wire.positions index))) :
    Set.InjOn (fun index => (points point wire).getD index 0)
      (Finset.range (points point wire).length) := by
  intro a ha b hb same
  have aBound : a < queryCount branch := by simpa [points] using Finset.mem_range.mp ha
  have bBound : b < queryCount branch := by simpa [points] using Finset.mem_range.mp hb
  have equal : (⟨a, aBound⟩ : Fin (queryCount branch)) = ⟨b, bBound⟩ := by
    apply distinct
    simpa [points, List.getD_eq_getElem?_getD, aBound, bBound] using same
  exact congrArg Fin.val equal

/-- All five checks follow from the calculated complete restore output. -/
theorem calculated_response_at_query {branch : Branch} {Position : Type*}
    (point : Position → Goldilocks) (wire : WireFields branch Position)
    (matrix : Matrix)
    (distinct : Function.Injective (fun index => point (wire.positions index)))
    (row : MaskRow) (index : Fin (queryCount branch)) :
    (responsePolynomials (calculatedResponse point wire matrix) row).eval
      (point (wire.positions index)) =
      (∑ column : Column, wire.sourceCells index column * matrix column row) +
        wire.maskingEvals index row := by
  have calculated := successful_restore_evaluation
    (points point wire) (values wire matrix row) (highWords wire row)
    (restoredWords point wire matrix row)
    (restoration_returns_calculated_words point wire matrix row)
    (typed_point_injection_implies_restore_distinct point wire distinct)
    index.val (by simp [points])
  simpa [responsePolynomials, calculatedResponse, points, values,
    List.getD_eq_getElem?_getD] using calculated

/-- Exact source-cell and masking readback equalities. These must eventually
be obtained from the family-specific authenticated leaf parser. They do not
assert query membership in the agreement support. -/
structure SourceReadback {branch : Branch} {Position : Type*}
    (wire : WireFields branch Position)
    (data : Nat → Position → Goldilocks) (masks : MaskRow → Position → Goldilocks) : Prop where
  source : ∀ index column, wire.sourceCells index column = data column.val (wire.positions index)
  masking : ∀ index row, wire.maskingEvals index row = masks row (wire.positions index)

theorem mixture_eq_fin_sum {Position : Type*}
    (data : Nat → Position → Goldilocks) (masks : MaskRow → Position → Goldilocks)
    (matrix : Matrix) (row : MaskRow) (index : Position) :
    mixedWord data masks (extendCoefficients matrix) 140 row index =
      masks row index + ∑ column : Column, matrix column row * data column.val index := by
  rw [mixed_word_eq_sum, ← Fin.sum_univ_eq_sum_range]
  congr 1

/-- Prior FPP response coefficients are represented by a response rule. The
full-polynomial equality is an explicit precommitment/readback obligation;
it is stronger than agreement only at the sampled query. -/
theorem query_agrees_with_prior_response
    {branch : Branch} {Position : Type*} [Fintype Position]
    (point : Position → Goldilocks) (wire : WireFields branch Position)
    (matrix : Matrix) (data : Nat → Position → Goldilocks)
    (masks : MaskRow → Position → Goldilocks)
    (response : Matrix → BoundedResponse Goldilocks MaskRow (degree branch))
    (distinct : Function.Injective (fun index => point (wire.positions index)))
    (readback : SourceReadback wire data masks)
    (fppBinding : response matrix = calculatedResponse point wire matrix)
    (index : Fin (queryCount branch)) :
    wire.positions index ∈ responseSupport point (degree branch) data masks response matrix := by
  rw [responseSupport, mem_agreement]
  intro row
  rw [fppBinding]
  rw [calculated_response_at_query point wire matrix distinct row index,
    mixture_eq_fin_sum]
  rw [readback.masking]
  have sumEq : (∑ column : Column, wire.sourceCells index column * matrix column row) =
      ∑ column : Column, matrix column row * data column.val (wire.positions index) := by
    apply Finset.sum_congr rfl
    intro column _
    rw [readback.source]
    exact mul_comm _ _
  rw [sumEq, add_comm]

end
end HegemonCrypto.SmallWood.NativeLaunchRelationModelResponse
