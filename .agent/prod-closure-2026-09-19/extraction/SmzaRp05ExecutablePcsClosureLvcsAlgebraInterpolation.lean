import SmzaRp05ExecutablePcsClosureLvcsAlgebraBlocks
import SmzaRp04TracePrefixes
import Mathlib.LinearAlgebra.Lagrange

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureLvcsAlgebra

open SmzaRp05LvcsWireProjection
open Polynomial
open scoped BigOperators

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 12000

/-- The executable finite product is exactly the evaluated Lagrange basis,
including evaluation at interpolation nodes. No division-by-nonzero premise
or probabilistic event is necessary for this algebraic identity. -/
theorem consecutive_basis_eq_lagrange (count : Nat) (index : Fin count) (point : F) :
    consecutiveBasis count index.val point =
      (Lagrange.basis (Finset.univ : Finset (Fin count))
        (fun j => (j.val : F)) index).eval point := by
  have productForm : consecutiveBasis count index.val point =
      ∏ j : Fin count, if index = j then 1 else
        (point - (j.val : F)) * (((index.val : F) - (j.val : F))⁻¹) := by
    unfold consecutiveBasis
    rw [← Fin.prod_univ_eq_prod_range]
    apply Finset.prod_congr rfl
    intro j _
    simp [Fin.ext_iff]
  rw [productForm, Lagrange.basis, Polynomial.eval_prod]
  rw [← Finset.mul_prod_erase (Finset.univ : Finset (Fin count))
    (fun j => if index = j then (1 : F) else
      (point - (j.val : F)) * (((index.val : F) - (j.val : F))⁻¹))
    (Finset.mem_univ index)]
  simp only [ite_true, one_mul]
  apply Finset.prod_congr rfl
  intro j member
  have different : index ≠ j := (Finset.mem_erase.mp member).1.symm
  simp [different, Lagrange.basisDivisor, mul_comm]

/-- Exact finite-list interpolation semantics of the native evaluator. -/
theorem evaluate_consecutive_ofFn (count : Nat) (values : Fin count → F) (point : F) :
    evaluateConsecutive (List.ofFn values) point =
      (Lagrange.interpolate (Finset.univ : Finset (Fin count))
        (fun index => (index.val : F)) values).eval point := by
  unfold evaluateConsecutive
  simp only [List.length_ofFn]
  rw [← Fin.sum_univ_eq_sum_range]
  rw [Lagrange.interpolate_apply, Polynomial.eval_finsetSum]
  apply Finset.sum_congr rfl
  intro index _
  rw [consecutive_basis_eq_lagrange count index point]
  simp [List.getD_eq_getElem?_getD, index.isLt]

def consecutivePolynomial (values : List F) : F[X] :=
  Lagrange.interpolate (Finset.univ : Finset (Fin values.length))
    (fun index => (index.val : F)) (fun index => values.getD index.val 0)

theorem evaluate_consecutive_eq_polynomial (values : List F) (point : F) :
    evaluateConsecutive values point = (consecutivePolynomial values).eval point := by
  have canonical : List.ofFn (fun index : Fin values.length => values.getD index.val 0) = values := by
    apply List.ext_getElem
    · simp
    · intro index leftBound rightBound
      simp
  have evaluated := evaluate_consecutive_ofFn values.length
    (fun index => values.getD index.val 0) point
  rw [canonical] at evaluated
  exact evaluated

/-- This is the exact abstract query polynomial used by TwelveLvcsChecks.
The only data bridge is the rotated list's equality to the decoded payload
evaluations, to be derived by the wire/record readback owner. -/
theorem decoded_query_polynomial_evaluation
    (payload : V8SmzaOracleParser.Payload) (combination : SmzaQ38LvcsOpening.Combination)
    (rotated : List F) (point : F)
    (decoded : rotated = List.ofFn
      (SmzaRp04TracePrefixes.queryEvaluations payload combination)) :
    (SmzaRp04TracePrefixes.queryPolynomial payload combination).eval point =
      evaluateConsecutive rotated point := by
  rw [decoded]
  change (Lagrange.interpolate (Finset.univ : Finset (Fin 406))
      (fun index => (index.val : F))
      (SmzaRp04TracePrefixes.queryEvaluations payload combination)).eval point =
    evaluateConsecutive
      (List.ofFn (SmzaRp04TracePrefixes.queryEvaluations payload combination)) point
  exact (evaluate_consecutive_ofFn 406
    (SmzaRp04TracePrefixes.queryEvaluations payload combination) point).symm

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureLvcsAlgebra
