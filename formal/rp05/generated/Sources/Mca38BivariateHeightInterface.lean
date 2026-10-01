import Mca38PrimitiveFactorDegreeBudget
import Mca38ActualRootSourceHeight

namespace HegemonCrypto.SmallWood.Mca38Published
noncomputable section
set_option autoImplicit false
variable {K : Type*} [Field K]

theorem bivariate_swap_coeff_coeff
    (F : Polynomial (Polynomial K)) (i j : ℕ) :
    ((Polynomial.Bivariate.swap F).coeff j).coeff i = (F.coeff i).coeff j := by
  induction F using Polynomial.induction_on' with
  | add p q hp hq =>
    simp only [map_add, Polynomial.coeff_add, hp, hq]
  | monomial n p =>
    rw [Polynomial.Bivariate.swap_monomial]
    by_cases h : n = i
    · subst n
      simp only [Polynomial.coeff_mul_C, Polynomial.coeff_map,
        Polynomial.coeff_C_mul, Polynomial.coeff_X_pow,
        Polynomial.coeff_monomial]
      simp only [if_true, mul_one]
    · simp only [Polynomial.coeff_mul_C, Polynomial.coeff_map,
        Polynomial.coeff_C_mul, Polynomial.coeff_X_pow,
        Polynomial.coeff_monomial, if_neg h, if_neg (Ne.symm h),
        mul_zero, Polynomial.coeff_zero]

theorem coefficient_natDegree_le_bivariateHeight
    (F : Polynomial (Polynomial K)) (i : ℕ) :
    (F.coeff i).natDegree ≤ bivariateCoefficientHeight F := by
  apply Polynomial.natDegree_le_iff_coeff_eq_zero.mpr
  intro j hj
  rw [← bivariate_swap_coeff_coeff F i j,
    Polynomial.coeff_eq_zero_of_natDegree_lt hj, Polynomial.coeff_zero]

theorem coefficientVariableSwap_eq_bivariateSwap
    (F : Polynomial (Polynomial K)) :
    coefficientVariableSwap F = Polynomial.Bivariate.swap F := by
  induction F using Polynomial.induction_on' with
  | add p q hp hq => simp only [map_add, hp, hq]
  | monomial n p =>
    simp only [← Polynomial.C_mul_X_pow_eq_monomial, map_mul, map_pow,
      coefficientVariableSwap_C, coefficientVariableSwap_X,
      Polynomial.Bivariate.swap_C, Polynomial.Bivariate.swap_Y]

theorem coefficient_natDegree_le_variableSwap
    (F : Polynomial (Polynomial K)) (i : ℕ) :
    (F.coeff i).natDegree ≤ (coefficientVariableSwap F).natDegree := by
  rw [coefficientVariableSwap_eq_bivariateSwap]
  exact coefficient_natDegree_le_bivariateHeight F i

end
end HegemonCrypto.SmallWood.Mca38Published
