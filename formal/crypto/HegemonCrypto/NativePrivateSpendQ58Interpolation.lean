/- Draft private-spend degree-13169 finite recovery instantiation.
Kernel check pending. No source/chronology/QROM bridge is asserted. -/
import HegemonCrypto.NativePrivateSpendQ58Parameters
import Mathlib.LinearAlgebra.FiniteDimensional.Lemmas
import Mathlib.LinearAlgebra.Dimension.Constructions
import Mathlib.Data.Fintype.BigOperators

/-!
The actual finite interpolation matrix for the analysis-only cutoff `360448`.

This file does not change the protocol degree, q58 sample size, or proof bytes.
Unlike `NativePrivateSpendQ58Parameters`, it constructs the coefficient and equation
index types, the concrete Hasse matrix for arbitrary source words, and a nonzero
kernel vector.  Specialization, arbitrary-support multiplicity, and the global
factor partition are deliberately left to subsequent modules.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58Interpolation

open scoped BigOperators
noncomputable section
set_option autoImplicit false

open HegemonCrypto.SmallWood.NativePrivateSpendQ58Parameters

/-- A coefficient of `X^i Y^j Z^h` in the 360448-cutoff interpolant. -/
abbrev CoefficientIndex :=
  Σ j : Fin yBound,
    Fin (xBound - degree * j.val) × Fin (zBound - j.val)

/-- A Hasse equation at a domain point, derivative order `(r,s)`, and
coefficient `Z^t`. -/
abbrev EquationIndex :=
  Fin domain ×
    (Σ s : Fin multiplicity,
      Fin (multiplicity - s.val) × Fin (zBound - s.val))

theorem coefficientIndex_card_eq_variableCount :
    Fintype.card CoefficientIndex = variableCount := by
  simp only [CoefficientIndex, Fintype.card_sigma, Fintype.card_prod,
    Fintype.card_fin]
  rw [variableCount]
  exact Fin.sum_univ_eq_sum_range
    (fun j : ℕ => (xBound - degree * j) * (zBound - j)) yBound

theorem equationIndex_card_eq_equationCount :
    Fintype.card EquationIndex = equationCount := by
  simp only [EquationIndex, Fintype.card_prod, Fintype.card_sigma,
    Fintype.card_fin]
  simp only [HegemonCrypto.SmallWood.NativePrivateSpendQ58Parameters.equationCount,
    HegemonCrypto.SmallWood.NativePrivateSpendQ58Parameters.domain,
    HegemonCrypto.SmallWood.NativePrivateSpendQ58Parameters.multiplicity,
    HegemonCrypto.SmallWood.NativePrivateSpendQ58Parameters.zBound]
  congr 1

theorem coefficientIndex_card :
    Fintype.card CoefficientIndex = 1776948361870 := by
  rw [coefficientIndex_card_eq_variableCount, exact_variable_count]

theorem equationIndex_card :
    Fintype.card EquationIndex = 1761314078720 := by
  rw [equationIndex_card_eq_equationCount, exact_equation_count]

theorem strictly_more_coefficients :
    Fintype.card EquationIndex < Fintype.card CoefficientIndex := by
  rw [equationIndex_card_eq_equationCount,
    coefficientIndex_card_eq_variableCount]
  exact variable_count_strict_surplus

theorem coefficient_weighted_degree (v : CoefficientIndex) :
    v.2.1.val + degree * v.1.val < xBound := by
  have h := v.2.1.isLt
  omega

theorem coefficient_z_specialization_degree (v : CoefficientIndex) :
    v.1.val + v.2.2.val < zBound := by
  have h := v.2.2.isLt
  omega

variable {K : Type*} [Field K]

/-- Finite-dimensional linear algebra supplies an actual nonzero kernel vector. -/
theorem exists_nonzero_matrix_solution {I J : Type*} [Fintype I] [Fintype J]
    (hcard : Fintype.card J < Fintype.card I) (matrix : J → I → K) :
    ∃ coeff : I → K, coeff ≠ 0 ∧ ∀ e, (∑ v, coeff v * matrix e v) = 0 := by
  let L : (I → K) →ₗ[K] (J → K) :=
    { toFun := fun coeff e => ∑ v, coeff v * matrix e v
      map_add' := by
        intro a b
        funext e
        simp only [Pi.add_apply, add_mul, Finset.sum_add_distrib]
      map_smul' := by
        intro scalar a
        funext e
        simp only [Pi.smul_apply, smul_eq_mul, mul_assoc,
          Finset.mul_sum, RingHom.id_apply] }
  have hdim : Module.finrank K (J → K) < Module.finrank K (I → K) := by
    simpa only [Module.finrank_fintype_fun_eq_card] using hcard
  have hk : LinearMap.ker L ≠ ⊥ := LinearMap.ker_ne_bot_of_finrank_lt hdim
  obtain ⟨coeff, hmem, hne⟩ := Submodule.exists_mem_ne_zero_of_ne_bot hk
  refine ⟨coeff, hne, ?_⟩
  have hz : L coeff = 0 := LinearMap.mem_ker.mp hmem
  intro e
  exact congrFun hz e


/-- The coefficient of `Z^t` in the `(r,s)` Hasse derivative after
`Y = U(x) + Z*V(x)`.  Out-of-range binomial coefficients contribute zero
through the explicit guard. -/
def hasseCoefficient (point U V : Fin domain → K)
    (e : EquationIndex) (v : CoefficientIndex) : K :=
  let j := v.1.val
  let i := v.2.1.val
  let h := v.2.2.val
  let s := e.2.1.val
  let r := e.2.2.1.val
  let t := e.2.2.2.val
  if h ≤ t ∧ t - h ≤ j - s then
    (Nat.choose i r : K) * (Nat.choose j s : K) *
      (Nat.choose (j - s) (t - h) : K) *
      point e.1 ^ (i - r) * U e.1 ^ (j - s - (t - h)) *
      V e.1 ^ (t - h)
  else 0

/-- The concrete homogeneous Hasse system for arbitrary point and source
words at the 360448 analysis cutoff. -/
def hasseMap (point U V : Fin domain → K) :
    (CoefficientIndex → K) →ₗ[K] (EquationIndex → K) where
  toFun coefficient e :=
    ∑ v, coefficient v * hasseCoefficient point U V e v
  map_add' a b := by
    funext e
    simp only [Pi.add_apply, add_mul, Finset.sum_add_distrib]
  map_smul' scalar a := by
    funext e
    simp only [Pi.smul_apply, smul_eq_mul, mul_assoc,
      Finset.mul_sum, RingHom.id_apply]

/-- Every actual matrix generated from arbitrary evaluation points and source
words has a nonzero coefficient table satisfying all 360448-cutoff Hasse
constraints.  The equations are conclusions, not hypotheses. -/
theorem exists_nonzero_hasse_table (point U V : Fin domain → K) :
    ∃ coefficient : CoefficientIndex → K, coefficient ≠ 0 ∧
      ∀ e : EquationIndex,
        (∑ v, coefficient v * hasseCoefficient point U V e v) = 0 := by
  exact exists_nonzero_matrix_solution
    strictly_more_coefficients (hasseCoefficient point U V)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58Interpolation
