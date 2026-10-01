import SmzaRp05DecsResponseProjection

/-!
# Algebra of the literal DECS restoration output

The input is the ordinary successful `polyRestoreResponse` computation, not
an evaluation certificate. The list implementation's Lagrange expression is
identified with the library polynomial. Its emitted coefficient list denotes
that entire polynomial, including the proof-carried high coefficients. This
is a deterministic step toward the five MCA checks; it does not by itself
establish the Merkle leaf readback or identify role-decoded response arrays.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureAlgebra

open Polynomial
open SmzaRp05ExecutableRestore
open SmzaRp05DecsResponseProjection
open scoped BigOperators

set_option autoImplicit false
noncomputable section

theorem denote_list_sum (terms : List Expr) :
    denote (exprSum terms) = (terms.map denote).sum := by
  induction terms with
  | nil => simp [exprSum, denote]
  | cons head rest ih => simp [exprSum, denote, ih]

theorem denote_list_product_filterMap {α : Type} (indices : List α)
    (terms : α → Option Expr) :
    denote (exprProduct (indices.filterMap terms)) =
      (indices.map fun i => ((terms i).map denote).getD 1).prod := by
  induction indices with
  | nil => simp [exprProduct, denote]
  | cons head rest ih =>
      cases h : terms head <;> simp [h, exprProduct, denote, ih]

theorem response_basis_denotes_lagrange (points : FieldRow) (index : Nat) :
    denote (responseBasis points index) =
      Lagrange.basis (Finset.range points.length)
        (fun i => points.getD i 0) index := by
  rw [responseBasis, denote_list_product_filterMap]
  have factors :
      ((List.range points.length).map fun j =>
        ((if j = index then none else
          some (divisor (points.getD index 0) (points.getD j 0))).map
          denote).getD 1) =
      (List.range points.length).map (fun j =>
        if j ∈ (Finset.range points.length).erase index then
          Lagrange.basisDivisor (points.getD index 0) (points.getD j 0)
        else 1) := by
    apply List.map_congr_left
    intro j hj
    have bound : j < points.length := List.mem_range.mp hj
    by_cases same : j = index <;>
      simp [same, Finset.mem_erase, bound, denote_divisor]
  rw [factors, ← List.prod_toFinset _ List.nodup_range, List.toFinset_range]
  have filtered : (Finset.range points.length).filter
      (fun j => j ∈ (Finset.range points.length).erase index) =
      (Finset.range points.length).erase index := by
    ext j
    simp only [Finset.mem_filter, Finset.mem_erase]
    tauto
  rw [← Finset.prod_filter, filtered]
  rfl

theorem response_low_denotes_interpolate (points values : FieldRow) :
    denote (responseLowPolynomial points values) =
      Lagrange.interpolate (Finset.range points.length)
        (fun i => points.getD i 0) (fun i => values.getD i 0) := by
  rw [responseLowPolynomial, denote_list_sum]
  simp only [List.map_map, Function.comp_def, denote,
    Polynomial.monomial_zero_left, response_basis_denotes_lagrange]
  rw [← List.sum_toFinset _ List.nodup_range, List.toFinset_range]
  exact (Lagrange.interpolate_apply _ _ _).symm

theorem response_high_denotes_sum (opened : Nat) (high : FieldRow) :
    denote (responseHighPolynomial opened high) =
      ∑ i ∈ Finset.range high.length,
        Polynomial.monomial (opened + i) (high.getD i 0) := by
  rw [responseHighPolynomial, denote_list_sum]
  simp only [List.map_map, Function.comp_def, denote]
  rw [← List.sum_toFinset _ List.nodup_range, List.toFinset_range]

def restoredExpression (points values high : FieldRow) : Expr :=
  let shifted := responseHighPolynomial points.length high
  .add (responseLowPolynomial points
    ((values.zip points).map fun pair => pair.1 - evalExpr shifted pair.2)) shifted

theorem residual_at (points values : FieldRow) (expression : Expr)
    (sameLength : points.length = values.length)
    (index : Nat) (bound : index < points.length) :
    ((values.zip points).map fun pair => pair.1 - evalExpr expression pair.2).getD
      index 0 = values.getD index 0 - evalExpr expression (points.getD index 0) := by
  have valueBound : index < values.length := by omega
  simp [List.getD_eq_getElem?_getD, valueBound,
    List.getElem_zip, List.length_zip, sameLength]

theorem restored_expression_evaluation (points values high : FieldRow)
    (sameLength : points.length = values.length)
    (distinct : Set.InjOn (fun i => points.getD i 0) (Finset.range points.length))
    (index : Nat) (bound : index < points.length) :
    (denote (restoredExpression points values high)).eval (points.getD index 0) =
      values.getD index 0 := by
  simp only [restoredExpression, denote, Polynomial.eval_add,
    response_low_denotes_interpolate]
  rw [Lagrange.eval_interpolate_at_node _ distinct (Finset.mem_range.mpr bound),
    residual_at points values _ sameLength index bound]
  simp [evalExpr, eval_correct]

theorem restored_expression_coefficient_above (points values high : FieldRow)
    (distinct : Set.InjOn (fun i => points.getD i 0) (Finset.range points.length))
    (degree : Nat) (above : points.length + high.length ≤ degree) :
    (denote (restoredExpression points values high)).coeff degree = 0 := by
  simp only [restoredExpression, denote, Polynomial.coeff_add,
    response_low_denotes_interpolate, response_high_denotes_sum]
  have lowZero :
      (Lagrange.interpolate (Finset.range points.length)
        (fun i => points.getD i 0)
        (fun i => ((values.zip points).map fun pair => pair.1 -
          evalExpr (responseHighPolynomial points.length high) pair.2).getD i 0)).coeff
        degree = 0 := by
    apply Polynomial.coeff_eq_zero_of_degree_lt
    apply (Lagrange.degree_interpolate_lt _ distinct).trans_le
    have le : points.length ≤ degree := by omega
    simpa using (show (points.length : WithBot Nat) ≤ degree by exact_mod_cast le)
  rw [lowZero, zero_add, Polynomial.finsetSum_coeff]
  apply Finset.sum_eq_zero
  intro i hi
  have hi' := Finset.mem_range.mp hi
  have different : points.length + i ≠ degree := by omega
  simp [Polynomial.coeff_monomial, different]

/-- Mathematical interpretation of exactly the source-emitted coefficient
list. The list is not replaced with an independently chosen polynomial. -/
def coefficientPolynomial (coefficients : FieldRow) : Goldilocks[X] :=
  ∑ i ∈ Finset.range coefficients.length,
    Polynomial.monomial i (coefficients.getD i 0)

theorem coefficient_polynomial_coeff (coefficients : FieldRow) (degree : Nat) :
    (coefficientPolynomial coefficients).coeff degree = coefficients.getD degree 0 := by
  classical
  simp only [coefficientPolynomial, Polynomial.finsetSum_coeff,
    Polynomial.coeff_monomial]
  by_cases bound : degree < coefficients.length
  · simp [bound]
  · simp [bound, List.getD_eq_getElem?_getD]

theorem successful_restore_emits_expression (points values high output : FieldRow)
    (success : polyRestoreResponse points values high = some output) :
    points.length = values.length ∧
      output = (List.range (points.length + high.length)).map
        (fun degree => coefficient (restoredExpression points values high) degree) := by
  by_cases sameLength : points.length = values.length
  · simp [polyRestoreResponse, sameLength] at success
    exact ⟨sameLength, by simpa only [restoredExpression, sameLength] using success.symm⟩
  · simp [polyRestoreResponse, sameLength] at success

/-- Complete coefficient serialization preserves the restored polynomial;
the upper-coefficient vanishing fact is proved from the interpolation degree,
not passed in as a correctness certificate. -/
theorem successful_restore_polynomial (points values high output : FieldRow)
    (success : polyRestoreResponse points values high = some output)
    (distinct : Set.InjOn (fun i => points.getD i 0) (Finset.range points.length)) :
    coefficientPolynomial output = denote (restoredExpression points values high) := by
  obtain ⟨_sameLength, emitted⟩ := successful_restore_emits_expression
    points values high output success
  subst output
  ext degree
  rw [coefficient_polynomial_coeff]
  by_cases bound : degree < points.length + high.length
  · simp [bound, coefficient_correct]
  · have above := Nat.le_of_not_gt bound
    rw [restored_expression_coefficient_above points values high distinct degree above]
    simp [List.getD_eq_getElem?_getD, bound]

/-- Every source-requested evaluation is recovered from the actual returned
coefficient list. The concrete DECS stage proves distinctness by its existing
decoded-point `Nodup` check; no new verifier guard is introduced here. -/
theorem successful_restore_evaluation (points values high output : FieldRow)
    (success : polyRestoreResponse points values high = some output)
    (distinct : Set.InjOn (fun i => points.getD i 0) (Finset.range points.length))
    (index : Nat) (bound : index < points.length) :
    (coefficientPolynomial output).eval (points.getD index 0) = values.getD index 0 := by
  rw [successful_restore_polynomial points values high output success distinct]
  exact restored_expression_evaluation points values high
    (successful_restore_emits_expression points values high output success).1
    distinct index bound

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureAlgebra
