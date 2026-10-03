import Mca38RbrGlobalMultiplicity
import Mathlib.Algebra.MvPolynomial.Basic

/-! The usable polynomial endpoint for the 65,536 round-by-round system.

The coefficient table is turned into an honest trivariate `MvPolynomial` and
an honest nested polynomial adapter.  All conclusions below are derived from
the finite Hasse kernel; no nonzero, degree, support, or vanishing conclusion
is supplied as a premise.
-/
namespace HegemonCrypto.SmallWood.Mca38RoundByRound
open scoped BigOperators
noncomputable section
set_option autoImplicit false
set_option maxRecDepth 20000

open HegemonCrypto.SmallWood.Mca38RoundByRoundParameters
open HegemonCrypto.SmallWood.Mca38RoundByRoundInterpolation
variable {K : Type*} [Field K]

def monomialExponent (v : CoefficientIndex) : Fin 3 →₀ ℕ :=
  Finsupp.single 0 v.2.1.val + Finsupp.single 1 v.1.val +
    Finsupp.single 2 v.2.2.val

theorem monomialExponent_injective : Function.Injective monomialExponent := by
  intro a b hab
  rcases a with ⟨j, i, h⟩
  rcases b with ⟨j', i', h'⟩
  have hj : j = j' := by
    apply Fin.ext
    simpa [monomialExponent] using congrArg (fun e => e 1) hab
  subst j'
  have hi : i = i' := by
    apply Fin.ext
    simpa [monomialExponent] using congrArg (fun e => e 0) hab
  subst i'
  have hh : h = h' := by
    apply Fin.ext
    simpa [monomialExponent] using congrArg (fun e => e 2) hab
  subst h'
  rfl

def interpolant (c : CoefficientIndex → K) : MvPolynomial (Fin 3) K :=
  ∑ v, MvPolynomial.monomial (monomialExponent v) (c v)

theorem interpolant_coeff (c : CoefficientIndex → K) (v : CoefficientIndex) :
    MvPolynomial.coeff (monomialExponent v) (interpolant c) = c v := by
  classical
  rw [interpolant, MvPolynomial.coeff_sum
    (Finset.univ : Finset CoefficientIndex)
    (fun v : CoefficientIndex => MvPolynomial.monomial (monomialExponent v) (c v))]
  simp only [MvPolynomial.coeff_monomial, monomialExponent_injective.eq_iff]
  simp

theorem interpolant_ne_zero (c : CoefficientIndex → K) (hc : c ≠ 0) :
    interpolant c ≠ 0 := by
  intro hz
  apply hc
  funext v
  have hv := interpolant_coeff c v
  rw [hz, MvPolynomial.coeff_zero] at hv
  exact hv.symm

theorem interpolant_nonzero_coefficient_bounds (c : CoefficientIndex → K)
    (e : Fin 3 →₀ ℕ) (hcoeff : MvPolynomial.coeff e (interpolant c) ≠ 0) :
    e 0 + degree * e 1 < xBound ∧ e 1 + e 2 < zBound := by
  classical
  rw [interpolant, MvPolynomial.coeff_sum
    (Finset.univ : Finset CoefficientIndex)
    (fun v : CoefficientIndex =>
      MvPolynomial.monomial (monomialExponent v) (c v)) e] at hcoeff
  obtain ⟨v, _, hv⟩ := Finset.exists_ne_zero_of_sum_ne_zero hcoeff
  have hev : monomialExponent v = e := by
    by_contra hne
    rw [MvPolynomial.coeff_monomial, if_neg hne] at hv
    exact hv rfl
  rw [← hev]
  constructor
  · simpa [monomialExponent] using coefficient_weighted_degree v
  · simpa [monomialExponent] using coefficient_z_specialization_degree v

def nestedPolynomial (c : CoefficientIndex → K) (z : K) :
    Polynomial (Polynomial K) :=
  ∑ v, Polynomial.C
      (Polynomial.C (c v * z ^ v.2.2.val) * Polynomial.X ^ v.2.1.val) *
    Polynomial.X ^ v.1.val

/- The factor-side orientation is outer Y, middle X, inner Z. -/
def trivariateNested (c : CoefficientIndex → K) :
    Polynomial (Polynomial (Polynomial K)) :=
  ∑ v, Polynomial.C
      (Polynomial.C (Polynomial.C (c v) * Polynomial.X ^ v.2.2.val) *
        Polynomial.X ^ v.2.1.val) * Polynomial.X ^ v.1.val

def nestedSourceOf (Q : MvPolynomial (Fin 3) K) :
    Polynomial (Polynomial (Polynomial K)) :=
  ∑ v, Polynomial.C
      (Polynomial.C (Polynomial.C (MvPolynomial.coeff (monomialExponent v) Q) *
        Polynomial.X ^ v.2.2.val) * Polynomial.X ^ v.2.1.val) *
      Polynomial.X ^ v.1.val

set_option linter.constructorNameAsVariable false in
theorem trivariateNested_coeff (c : CoefficientIndex → K) (v : CoefficientIndex) :
    (((trivariateNested c).coeff v.1.val).coeff v.2.1.val).coeff v.2.2.val =
      c v := by
  classical
  simp only [trivariateNested, Polynomial.finsetSum_coeff]
  rw [Finset.sum_eq_single v]
  · simp only [Polynomial.coeff_C_mul_X_pow, if_true]
  · intro b hb hne
    by_cases hj : v.1.val = b.1.val
    · rw [Polynomial.coeff_C_mul_X_pow, if_pos hj]
      by_cases hi : v.2.1.val = b.2.1.val
      · rw [Polynomial.coeff_C_mul_X_pow, if_pos hi]
        by_cases hh : v.2.2.val = b.2.2.val
        · have sameExponent : monomialExponent b = monomialExponent v := by
            simp only [monomialExponent, ← hj, ← hi, ← hh]
          exact (hne (monomialExponent_injective sameExponent)).elim
        · rw [Polynomial.coeff_C_mul_X_pow, if_neg hh]
      · rw [Polynomial.coeff_C_mul_X_pow, if_neg hi, Polynomial.coeff_zero]
    · rw [Polynomial.coeff_C_mul_X_pow, if_neg hj,
        Polynomial.coeff_zero, Polynomial.coeff_zero]
  · simp

theorem trivariateNested_ne_zero (c : CoefficientIndex → K) (hc : c ≠ 0) :
    trivariateNested c ≠ 0 := by
  intro hz
  apply hc
  funext v
  have hv := trivariateNested_coeff c v
  rw [hz, Polynomial.coeff_zero, Polynomial.coeff_zero,
    Polynomial.coeff_zero] at hv
  exact hv.symm

theorem nestedSourceOf_interpolant (c : CoefficientIndex → K) :
    nestedSourceOf (interpolant c) = trivariateNested c := by
  unfold nestedSourceOf trivariateNested
  apply Finset.sum_congr rfl
  intro v _
  rw [interpolant_coeff]

theorem trivariateNested_specialize_Z (c : CoefficientIndex → K) (z : K) :
    (trivariateNested c).map
      (Polynomial.mapRingHom (Polynomial.evalRingHom z)) = nestedPolynomial c z := by
  unfold trivariateNested nestedPolynomial
  simp [Polynomial.map_sum, Polynomial.map_mul, Polynomial.map_C,
    Polynomial.map_pow, Polynomial.coe_mapRingHom,
    Polynomial.eval_C, Polynomial.eval_X]

theorem interpolant_exact_coordinate_bounds (c : CoefficientIndex → K)
    (e : Fin 3 →₀ ℕ) (hcoeff : MvPolynomial.coeff e (interpolant c) ≠ 0) :
    e 0 < xBound ∧ e 1 < yBound ∧ e 2 < zBound := by
  classical
  rw [interpolant, MvPolynomial.coeff_sum
    (Finset.univ : Finset CoefficientIndex)
    (fun v : CoefficientIndex =>
      MvPolynomial.monomial (monomialExponent v) (c v)) e] at hcoeff
  obtain ⟨v, _, hv⟩ := Finset.exists_ne_zero_of_sum_ne_zero hcoeff
  have hev : monomialExponent v = e := by
    by_contra hne
    rw [MvPolynomial.coeff_monomial, if_neg hne] at hv
    exact hv rfl
  rw [← hev]
  refine ⟨?_, ?_, ?_⟩
  · have h := coefficient_weighted_degree v
    have he0 : (monomialExponent v) 0 = v.2.1.val := by
      simp [monomialExponent, Finsupp.add_apply]
    rw [he0]
    omega
  · have he1 : (monomialExponent v) 1 = v.1.val := by
      simp [monomialExponent, Finsupp.add_apply]
    rw [he1]
    exact v.1.isLt
  · have he2 : (monomialExponent v) 2 = v.2.2.val := by
      simp [monomialExponent, Finsupp.add_apply]
    rw [he2]
    have h := coefficient_z_specialization_degree v
    omega

theorem nestedPolynomial_eq_rbrInterpolant (c : CoefficientIndex → K) (z : K) :
    nestedPolynomial c z = nestedInterpolant c z := by
  rfl

theorem nestedPolynomial_specialization_identity
    (c : CoefficientIndex → K) (z : K) (P : Polynomial K) :
    (nestedPolynomial c z).eval P = specializedInterpolant c z P := by
  rw [nestedPolynomial_eq_rbrInterpolant]
  exact nestedInterpolant_eval c z P

theorem interpolant_to_nested_specialization_identity
    (c : CoefficientIndex → K) (z : K) (P : Polynomial K) :
    ((nestedSourceOf (interpolant c)).map
      (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval P =
      specializedInterpolant c z P := by
  rw [nestedSourceOf_interpolant, trivariateNested_specialize_Z]
  exact nestedPolynomial_specialization_identity c z P

theorem exists_rbr_polynomial_endpoint
    (point U V : Fin domain → K) (hinj : Function.Injective point) :
    ∃ c : CoefficientIndex → K, ∃ Q : MvPolynomial (Fin 3) K,
      Q = interpolant c ∧ Q ≠ 0 ∧ c ≠ 0 ∧
      trivariateNested c ≠ 0 ∧ nestedSourceOf Q ≠ 0 ∧
      (∀ e : EquationIndex,
        (∑ v, c v * hasseCoefficient point U V e v) = 0) ∧
      (∀ e : Fin 3 →₀ ℕ, MvPolynomial.coeff e Q ≠ 0 →
        e 0 + degree * e 1 < xBound ∧ e 1 + e 2 < zBound) ∧
      (∀ e : Fin 3 →₀ ℕ, MvPolynomial.coeff e Q ≠ 0 →
        e 0 < xBound ∧ e 1 < yBound ∧ e 2 < zBound) ∧
      (∀ (z : K) (P : Polynomial K), P.natDegree ≤ degree →
        ((nestedSourceOf Q).map
          (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval P =
          specializedInterpolant c z P) ∧
      (∀ (z : K) (P : Polynomial K), P.natDegree ≤ degree →
        (nestedPolynomial c z).eval P = specializedInterpolant c z P) ∧
      (∀ (z : K) (P : Polynomial K), P.natDegree ≤ degree →
        ∀ S : Finset (Fin domain), threshold ≤ S.card →
          (∀ a ∈ S, P.eval (point a) = U a + z * V a) →
          specializedInterpolant c z P = 0) := by
  obtain ⟨c, hc, hsolve⟩ := exists_nonzero_hasse_table point U V
  refine ⟨c, interpolant c, rfl, interpolant_ne_zero c hc, hc,
    trivariateNested_ne_zero c hc, ?_, hsolve, ?_, ?_, ?_, ?_, ?_⟩
  · rw [nestedSourceOf_interpolant]
    exact trivariateNested_ne_zero c hc
  · intro e he
    exact interpolant_nonzero_coefficient_bounds c e he
  · intro e he
    exact interpolant_exact_coordinate_bounds c e he
  · intro z P hP
    exact interpolant_to_nested_specialization_identity c z P
  · intro z P hP
    exact nestedPolynomial_specialization_identity c z P
  · intro z P hP S hcard hmatch
    exact actual_specialization_eq_zero_on_threshold_support
      c point U V hsolve z P hP S hcard
      (fun _ _ _ _ h => hinj h) hmatch

end
end HegemonCrypto.SmallWood.Mca38RoundByRound
