import Mca38RoundByRoundParameters
import Mca38GsInterpolationR3

/-!
The actual finite interpolation matrix for the analysis-only cutoff `65536`.

This file does not change the protocol degree, q38 sample size, or proof bytes.
Unlike `Mca38RoundByRoundParameters`, it constructs the coefficient and equation
index types, the concrete Hasse matrix for arbitrary source words, and a nonzero
kernel vector.  Specialization, arbitrary-support multiplicity, and the global
factor partition are deliberately left to subsequent modules.
-/
namespace HegemonCrypto.SmallWood.Mca38RoundByRoundInterpolation

open scoped BigOperators
noncomputable section
set_option autoImplicit false

open HegemonCrypto.SmallWood.Mca38RoundByRoundParameters

/-- A coefficient of `X^i Y^j Z^h` in the 65536-cutoff interpolant. -/
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
  simp only [HegemonCrypto.SmallWood.Mca38RoundByRoundParameters.equationCount,
    HegemonCrypto.SmallWood.Mca38RoundByRoundParameters.domain,
    HegemonCrypto.SmallWood.Mca38RoundByRoundParameters.multiplicity,
    HegemonCrypto.SmallWood.Mca38RoundByRoundParameters.zBound]
  congr 1

theorem coefficientIndex_card :
    Fintype.card CoefficientIndex = 1291494765825 := by
  rw [coefficientIndex_card_eq_variableCount, exact_variable_count]

theorem equationIndex_card :
    Fintype.card EquationIndex = 1258123427840 := by
  rw [equationIndex_card_eq_equationCount, exact_equation_count]

theorem strictly_more_coefficients :
    Fintype.card EquationIndex < Fintype.card CoefficientIndex := by
  rw [equationIndex_card_eq_equationCount,
    coefficientIndex_card_eq_variableCount]
  exact proposed_variable_count_strict_surplus

theorem coefficient_weighted_degree (v : CoefficientIndex) :
    v.2.1.val + degree * v.1.val < xBound := by
  have h := v.2.1.isLt
  omega

theorem coefficient_z_specialization_degree (v : CoefficientIndex) :
    v.1.val + v.2.2.val < zBound := by
  have h := v.2.2.isLt
  omega

variable {K : Type*} [Field K]

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
words at the 65536 analysis cutoff. -/
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
words has a nonzero coefficient table satisfying all 65536-cutoff Hasse
constraints.  The equations are conclusions, not hypotheses. -/
theorem exists_nonzero_hasse_table (point U V : Fin domain → K) :
    ∃ coefficient : CoefficientIndex → K, coefficient ≠ 0 ∧
      ∀ e : EquationIndex,
        (∑ v, coefficient v * hasseCoefficient point U V e v) = 0 := by
  exact HegemonCrypto.SmallWood.Mca38Published.exists_nonzero_matrix_solution
    strictly_more_coefficients (hasseCoefficient point U V)

end
end HegemonCrypto.SmallWood.Mca38RoundByRoundInterpolation
