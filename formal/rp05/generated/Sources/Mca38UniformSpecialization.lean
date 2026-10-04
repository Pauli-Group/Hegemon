import Mca38SimpleFactorStartR2
import Mca38EliminationDegree
import Mathlib.RingTheory.Polynomial.Resultant.Basic

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {K L : Type*} [Field K] [Field L]

/-- The concrete polynomial whose nonvanishing preserves degree and simple
roots under specialization of the coefficient variable. -/
def simpleSpecializationException (f : Polynomial (Polynomial K)) : Polynomial K :=
  f.leadingCoeff * f.resultant f.derivative

theorem resultant_coefficient_height
    (f g : Polynomial (Polynomial K)) (D m n : ℕ)
    (hf : ∀ j, (f.coeff j).natDegree ≤ D)
    (hg : ∀ j, (g.coeff j).natDegree ≤ D) :
    (f.resultant g m n).natDegree ≤ (m + n) * D := by
  have hentry : ∀ i j, ((Polynomial.sylvester f g m n) i j).natDegree ≤ D := by
    intro i j
    refine Fin.addCases (fun j => ?_) (fun j => ?_) j
    · simp only [Polynomial.sylvester, Matrix.of_apply, Fin.addCases_left]
      split_ifs
      · exact hg _
      · simp
    · simp only [Polynomial.sylvester, Matrix.of_apply, Fin.addCases_right]
      split_ifs
      · exact hf _
      · simp
  simpa [Polynomial.resultant] using
    elimination_determinant_natDegree (Polynomial.sylvester f g m n)
      (fun _ => D) hentry

theorem simpleSpecializationException_degree
    (f : Polynomial (Polynomial K)) (D : ℕ)
    (hpositive : 0 < f.natDegree)
    (hf : ∀ j, (f.coeff j).natDegree ≤ D) :
    (simpleSpecializationException f).natDegree ≤ 2 * f.natDegree * D := by
  have hd : ∀ j, (f.derivative.coeff j).natDegree ≤ D := by
    intro j
    rw [Polynomial.coeff_derivative]
    have hdegree : ((f.coeff (j + 1)) * ((j + 1 : ℕ) : Polynomial K)).natDegree ≤ D := by
      calc
        _ ≤ (f.coeff (j + 1)).natDegree +
              ((j + 1 : ℕ) : Polynomial K).natDegree := Polynomial.natDegree_mul_le
        _ ≤ D := by
          simpa only [Polynomial.natDegree_natCast, add_zero] using hf (j + 1)
    simpa only [Nat.cast_add, Nat.cast_one] using hdegree
  have hr := resultant_coefficient_height f f.derivative D
    f.natDegree f.derivative.natDegree hf hd
  have hder := Polynomial.natDegree_derivative_le f
  have hl : f.leadingCoeff.natDegree ≤ D := hf f.natDegree
  unfold simpleSpecializationException
  calc
    (f.leadingCoeff * f.resultant f.derivative).natDegree ≤
        f.leadingCoeff.natDegree + (f.resultant f.derivative).natDegree :=
      Polynomial.natDegree_mul_le
    _ ≤ D + (f.natDegree + f.derivative.natDegree) * D := Nat.add_le_add hl hr
    _ = (f.natDegree + f.derivative.natDegree + 1) * D := by ring
    _ ≤ 2 * f.natDegree * D := Nat.mul_le_mul_right D (by omega)

theorem simpleSpecializationException_ne_zero
    (f : Polynomial (Polynomial K)) (φ : Polynomial K →+* L)
    (hinj : Function.Injective φ) (hpositive : 0 < f.natDegree)
    (hsep : (f.map φ).Separable) :
    simpleSpecializationException f ≠ 0 := by
  have hf : f ≠ 0 := by intro h; simp [h] at hpositive
  have hcop : IsCoprime (f.map φ) (f.derivative.map φ) := by
    simpa only [Polynomial.derivative_map] using
      ((Polynomial.separable_def _).mp hsep)
  have hres := Polynomial.resultant_ne_zero (f.map φ) (f.derivative.map φ) hcop
  simp only [Polynomial.natDegree_map_eq_of_injective hinj,
    Polynomial.resultant_map_map] at hres
  have hr : f.resultant f.derivative ≠ 0 := by
    intro h
    apply hres
    rw [h, map_zero]
  exact mul_ne_zero (Polynomial.leadingCoeff_ne_zero.mpr hf) hr

/-- The derivative coprimality is obtained from the actual resultant Bezout
identity. No specialized separability or specialized-root premise is used. -/
theorem specialization_simple_of_exception_ne_zero
    (f : Polynomial (Polynomial K)) (hpositive : 0 < f.natDegree) (x : K)
    (hx : (simpleSpecializationException f).eval x ≠ 0) :
    (specializeCoefficientVariable f x).natDegree = f.natDegree ∧
      (specializeCoefficientVariable f x).Separable := by
  have hparts : f.leadingCoeff.eval x ≠ 0 ∧ (f.resultant f.derivative).eval x ≠ 0 := by
    simpa only [simpleSpecializationException, Polynomial.eval_mul, mul_ne_zero_iff] using hx
  refine ⟨Polynomial.natDegree_map_of_leadingCoeff_ne_zero
    (Polynomial.evalRingHom x) hparts.1, ?_⟩
  obtain ⟨a, b, _, _, hbez⟩ := Polynomial.exists_mul_add_mul_eq_C_resultant
    f f.derivative (le_refl _) (le_refl _) (Or.inl (Nat.ne_of_gt hpositive))
  let ev : Polynomial K →+* K := Polynomial.evalRingHom x
  have hm : specializeCoefficientVariable f x * a.map ev +
      (specializeCoefficientVariable f x).derivative * b.map ev =
        Polynomial.C ((f.resultant f.derivative).eval x) := by
    simpa only [specializeCoefficientVariable, ev, Polynomial.map_add,
      Polynomial.map_mul, Polynomial.map_C, Polynomial.derivative_map,
      Polynomial.coe_evalRingHom] using congrArg (Polynomial.map ev) hbez
  change IsCoprime (specializeCoefficientVariable f x)
    (specializeCoefficientVariable f x).derivative
  refine ⟨a.map ev * Polynomial.C ((f.resultant f.derivative).eval x)⁻¹,
    b.map ev * Polynomial.C ((f.resultant f.derivative).eval x)⁻¹, ?_⟩
  calc
    a.map ev * Polynomial.C ((f.resultant f.derivative).eval x)⁻¹ *
          specializeCoefficientVariable f x +
        b.map ev * Polynomial.C ((f.resultant f.derivative).eval x)⁻¹ *
          (specializeCoefficientVariable f x).derivative =
      (specializeCoefficientVariable f x * a.map ev +
        (specializeCoefficientVariable f x).derivative * b.map ev) *
          Polynomial.C ((f.resultant f.derivative).eval x)⁻¹ := by ring
    _ = Polynomial.C ((f.resultant f.derivative).eval x) *
        Polynomial.C ((f.resultant f.derivative).eval x)⁻¹ := by rw [hm]
    _ = 1 := by rw [← Polynomial.C_mul, mul_inv_cancel₀ hparts.2, Polynomial.C_1]

/-- A common candidate set larger than the proved exception degree contains
a valid specialization. The exception polynomial is constructed internally. -/
theorem exists_simple_specialization
    (f : Polynomial (Polynomial K)) (φ : Polynomial K →+* L)
    (hinj : Function.Injective φ) (hpositive : 0 < f.natDegree)
    (hsep : (f.map φ).Separable) (D : ℕ)
    (hf : ∀ j, (f.coeff j).natDegree ≤ D) (candidates : Finset K)
    (hsize : 2 * f.natDegree * D < candidates.card) :
    ∃ x ∈ candidates, (specializeCoefficientVariable f x).Separable ∧
      0 < (specializeCoefficientVariable f x).natDegree := by
  classical
  have hnonzero := simpleSpecializationException_ne_zero f φ hinj hpositive hsep
  have hex : ∃ x ∈ candidates, (simpleSpecializationException f).eval x ≠ 0 := by
    by_contra h
    have hzero : ∀ x ∈ candidates, (simpleSpecializationException f).eval x = 0 := by
      intro x hx
      by_contra hn
      exact h ⟨x, hx, hn⟩
    have hcard : candidates.card ≤ (simpleSpecializationException f).natDegree := by
      apply Polynomial.card_le_degree_of_subset_roots
      intro x hx
      exact (Polynomial.mem_roots hnonzero).mpr (hzero x hx)
    exact (Nat.not_lt_of_ge
      (hcard.trans (simpleSpecializationException_degree f D hpositive hf))) hsize
  obtain ⟨x, hx, hgood⟩ := hex
  have hs := specialization_simple_of_exception_ne_zero f hpositive x hgood
  exact ⟨x, hx, hs.2, hs.1.symm ▸ hpositive⟩

/-- All actual factors share one valid starting X-coordinate. The finite
product exception and its degree are proved internally, so the hypothesis
does not assume a uniform specialization or an exceptional-label count. -/
theorem exists_uniform_simple_specialization {ι : Type*}
    (s : Finset ι) (f : ι → Polynomial (Polynomial K))
    (φ : Polynomial K →+* L) (hinj : Function.Injective φ)
    (hpositive : ∀ i ∈ s, 0 < (f i).natDegree)
    (hsep : ∀ i ∈ s, ((f i).map φ).Separable) (D : ι → ℕ)
    (hf : ∀ i ∈ s, ∀ j, ((f i).coeff j).natDegree ≤ D i)
    (candidates : Finset K)
    (hsize : (∑ i ∈ s, 2 * (f i).natDegree * D i) < candidates.card) :
    ∃ x ∈ candidates, ∀ i ∈ s,
      (specializeCoefficientVariable (f i) x).Separable ∧
      0 < (specializeCoefficientVariable (f i) x).natDegree := by
  classical
  let Δ : Polynomial K := ∏ i ∈ s, simpleSpecializationException (f i)
  have hnonzero : Δ ≠ 0 := Finset.prod_ne_zero_iff.mpr (fun i hi =>
    simpleSpecializationException_ne_zero (f i) φ hinj (hpositive i hi) (hsep i hi))
  have hdegree : Δ.natDegree ≤ ∑ i ∈ s, 2 * (f i).natDegree * D i := by
    exact (Polynomial.natDegree_prod_le s _).trans (Finset.sum_le_sum (fun i hi =>
      simpleSpecializationException_degree (f i) (D i) (hpositive i hi) (hf i hi)))
  have hex : ∃ x ∈ candidates, Δ.eval x ≠ 0 := by
    by_contra h
    have hcard : candidates.card ≤ Δ.natDegree := by
      apply Polynomial.card_le_degree_of_subset_roots
      intro x hx
      apply (Polynomial.mem_roots hnonzero).mpr
      by_contra hn
      exact h ⟨x, hx, hn⟩
    exact (Nat.not_lt_of_ge (hcard.trans hdegree)) hsize
  obtain ⟨x, hx, hgood⟩ := hex
  refine ⟨x, hx, ?_⟩
  intro i hi
  have hproduct : (∏ j ∈ s, (simpleSpecializationException (f j)).eval x) ≠ 0 := by
    simpa only [Δ, Polynomial.eval_prod] using hgood
  have hfactor := (Finset.prod_ne_zero_iff.mp hproduct) i hi
  have hs := specialization_simple_of_exception_ne_zero (f i) (hpositive i hi) x hfactor
  exact ⟨hs.2, hs.1.symm ▸ hpositive i hi⟩

end
end HegemonCrypto.SmallWood.Mca38Published
