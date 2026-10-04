import Mca38NestedFactorCoverage
import Mca38NestedContentExceptions

/-! Degree budgets for the actual nested Hasse interpolant. Direct variable
permutations avoid an arbitrary-MvPolynomial-factor conversion entirely. -/
namespace HegemonCrypto.SmallWood.Mca38NestedInterpolationHeights
open HegemonCrypto.SmallWood.Mca38NestedFactorCoverage
open HegemonCrypto.SmallWood.Mca38RoundByRound
open HegemonCrypto.SmallWood.Mca38RoundByRoundInterpolation
open HegemonCrypto.SmallWood.Mca38RoundByRoundParameters
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
variable {K : Type*} [Field K]

def term (a : K) (j i h : Nat) : Polynomial (Polynomial (Polynomial K)) :=
  Polynomial.C (Polynomial.C (Polynomial.C a * Polynomial.X^h) *
    Polynomial.X^i) * Polynomial.X^j

theorem term_Y_degree (a : K) (j i h : Nat) : (term a j i h).natDegree ≤ j := by
  apply Polynomial.natDegree_mul_le.trans
  simp only [Polynomial.natDegree_C, zero_add, Polynomial.natDegree_X_pow]
  rfl

theorem swap_degree_le {R : Type*} [CommRing R]
    (F : Polynomial (Polynomial R)) (d : Nat)
    (bound : ∀ i, (F.coeff i).natDegree ≤ d) :
    (Polynomial.Bivariate.swap F).natDegree ≤ d := by
  apply Polynomial.natDegree_le_iff_coeff_eq_zero.mpr
  intro j above
  apply Polynomial.ext
  intro i
  rw [HegemonCrypto.SmallWood.Mca38NestedContentExceptions.swap_coefficient,
    Polynomial.coeff_zero]
  exact Polynomial.coeff_eq_zero_of_natDegree_lt ((bound i).trans_lt above)

theorem term_X_degree (a : K) (j i h : Nat) : (xView (term a j i h)).natDegree ≤ i := by
  change (Polynomial.Bivariate.swap (term a j i h)).natDegree ≤ i
  apply swap_degree_le
  intro k
  rw [term, Polynomial.coeff_C_mul_X_pow]
  split_ifs
  · exact (Polynomial.natDegree_C_mul_le _ _).trans (by simp)
  · simp

theorem term_Z_degree (a : K) (j i h : Nat) : (zView (term a j i h)).natDegree ≤ h := by
  change (Polynomial.Bivariate.swap
    ((term a j i h).map (Polynomial.Bivariate.swap (R := K)).toRingHom)).natDegree ≤ h
  apply swap_degree_le
  intro k
  rw [Polynomial.coeff_map]
  apply swap_degree_le
  intro l
  rw [term, Polynomial.coeff_C_mul_X_pow]
  split_ifs
  · rw [Polynomial.coeff_C_mul_X_pow]
    split_ifs
    · exact (Polynomial.natDegree_C_mul_le _ _).trans (by simp)
    · simp
  · simp

/-- The three numerical budgets are derived from the actual finite monomial
index bounds, rather than supplied for a newly introduced source polynomial. -/
theorem actual_nested_interpolant_heights (c : CoefficientIndex → K) :
    (trivariateNested c).natDegree ≤ yBound ∧
    (xView (trivariateNested c)).natDegree ≤ xBound ∧
    (zView (trivariateNested c)).natDegree ≤ zBound := by
  have source : trivariateNested c =
      ∑ v : CoefficientIndex, term (c v) v.1.val v.2.1.val v.2.2.val := rfl
  rw [source, map_sum, map_sum]
  refine ⟨?_, ?_, ?_⟩
  · apply Polynomial.natDegree_sum_le_of_forall_le
    intro v _
    exact (term_Y_degree _ _ _ _).trans v.1.isLt.le
  · apply Polynomial.natDegree_sum_le_of_forall_le
    intro v _
    apply (term_X_degree _ _ _ _).trans
    have bound := coefficient_weighted_degree v
    omega
  · apply Polynomial.natDegree_sum_le_of_forall_le
    intro v _
    apply (term_Z_degree _ _ _ _).trans
    have bound := coefficient_z_specialization_degree v
    omega

end
end HegemonCrypto.SmallWood.Mca38NestedInterpolationHeights
