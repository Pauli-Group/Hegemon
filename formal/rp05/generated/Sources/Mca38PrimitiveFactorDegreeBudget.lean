import Mathlib.RingTheory.Polynomial.UniqueFactorization
import Mathlib.RingTheory.Polynomial.GaussLemma
import Mathlib.Algebra.Polynomial.Bivariate
import Mathlib.Algebra.Polynomial.BigOperators

/-! Actual finite primitive factorization with shared weighted degree budgets.
Content is retained explicitly; each primitive factor stays irreducible over
K(Z). The inner-variable height is the outer degree after swapping variables.
-/
namespace HegemonCrypto.SmallWood.Mca38Published
noncomputable section
set_option autoImplicit false
variable {K : Type*} [Field K]

/- The coefficient UFD supplies a normalized gcd structure by choice.  This is
constructed here, rather than being an additional hypothesis of the bound. -/
noncomputable instance coefficientNormalizedGCDMonoid :
    NormalizedGCDMonoid (Polynomial K) := Classical.arbitrary _

private theorem polynomial_ringHom_multiset_prod {R S : Type*}
    [CommRing R] [CommRing S] (φ : R →+* S) (fs : Multiset R) :
    φ fs.prod = (fs.map (fun H => φ H)).prod := by
  induction fs using Multiset.induction_on with
  | empty => simp
  | cons H fs ih =>
    simp only [Multiset.prod_cons, Multiset.map_cons, map_mul, ih]

def bivariateCoefficientHeight (F : Polynomial (Polynomial K)) : ℕ :=
  (Polynomial.Bivariate.swap F).natDegree

theorem bivariateCoefficientHeight_le_of_coeff_bound
    (F : Polynomial (Polynomial K)) (D : ℕ)
    (hD : ∀ i, (F.coeff i).natDegree ≤ D) :
    bivariateCoefficientHeight F ≤ D := by
  classical
  unfold bivariateCoefficientHeight
  conv_lhs => rw [← Polynomial.sum_monomial_eq F]
  rw [Polynomial.sum_def, map_sum]
  apply Polynomial.natDegree_sum_le_of_forall_le
  intro i _
  rw [Polynomial.Bivariate.swap_monomial]
  apply Polynomial.natDegree_mul_le.trans
  simpa only [Polynomial.natDegree_C, add_zero] using
    (Polynomial.natDegree_map_le.trans (hD i))

theorem actual_primitive_factor_degree_budget
    (F : Polynomial (Polynomial K)) (hF : F ≠ 0) :
    ∃ factors : Multiset (Polynomial (Polynomial K)),
      Associated factors.prod F.primPart ∧
      (∀ H ∈ factors, Irreducible H ∧ H.IsPrimitive ∧
        Irreducible (H.map (algebraMap (Polynomial K) (FractionRing (Polynomial K)))) ∧
        0 < H.natDegree) ∧
      (factors.map Polynomial.natDegree).sum = F.natDegree ∧
      (factors.map bivariateCoefficientHeight).sum ≤ bivariateCoefficientHeight F ∧
      Associated (Polynomial.C F.content * factors.prod) F := by
  classical
  obtain ⟨factors, hirr, hassoc⟩ :=
    WfDvdMonoid.exists_factors F.primPart F.primPart_ne_zero
  have hnz : (0 : Polynomial (Polynomial K)) ∉ factors := by
    intro h
    exact (hirr 0 h).ne_zero rfl
  have hprimitive : ∀ H ∈ factors, H.IsPrimitive := by
    intro H hH
    exact Polynomial.isPrimitive_of_dvd F.isPrimitive_primPart
      ((Multiset.dvd_prod hH).trans hassoc.dvd)
  have hT : (factors.map Polynomial.natDegree).sum = F.natDegree := by
    rw [← Polynomial.natDegree_multiset_prod factors hnz]
    exact (Polynomial.natDegree_eq_of_degree_eq
      (Polynomial.degree_eq_degree_of_associated hassoc)).trans F.natDegree_primPart
  let swap : Polynomial (Polynomial K) →+* Polynomial (Polynomial K) :=
    (Polynomial.Bivariate.swap (R := K)).toRingHom
  have swap_injective : Function.Injective swap :=
    (Polynomial.Bivariate.swap (R := K)).injective
  have hswap : Associated ((factors.map swap).prod) (swap F.primPart) := by
    have h : Associated (swap factors.prod) (swap F.primPart) := hassoc.map swap
    exact polynomial_ringHom_multiset_prod swap factors ▸ h
  have hswapnz : (0 : Polynomial (Polynomial K)) ∉ factors.map swap := by
    intro h
    obtain ⟨H, hH, heq⟩ := Multiset.mem_map.mp h
    have hzero : H = 0 := swap_injective (heq.trans (map_zero swap).symm)
    exact (hirr H hH).ne_zero hzero
  have hZ : (factors.map bivariateCoefficientHeight).sum ≤
      bivariateCoefficientHeight F := by
    have heq : (factors.map bivariateCoefficientHeight).sum =
        (swap F.primPart).natDegree := by
      calc
        _ = ((factors.map swap).map Polynomial.natDegree).sum := by
          rw [Multiset.map_map]
          rfl
        _ = ((factors.map swap).prod).natDegree :=
          (Polynomial.natDegree_multiset_prod _ hswapnz).symm
        _ = _ := Polynomial.natDegree_eq_of_degree_eq
          (Polynomial.degree_eq_degree_of_associated hswap)
    rw [heq]
    exact Polynomial.natDegree_le_of_dvd
      (_root_.map_dvd swap F.primPart_dvd)
      (fun h => hF (swap_injective (h.trans (map_zero swap).symm)))
  refine ⟨factors, hassoc, ?_, hT, hZ, ?_⟩
  · intro H hH
    have hmap := (Polynomial.IsPrimitive.irreducible_iff_irreducible_map_fraction_map
      (K := FractionRing (Polynomial K)) (hprimitive H hH)).mp (hirr H hH)
    refine ⟨hirr H hH, hprimitive H hH, hmap, ?_⟩
    have hpos := Polynomial.natDegree_pos_iff_degree_pos.mpr
      (Polynomial.degree_pos_of_irreducible hmap)
    rw [Polynomial.natDegree_map_eq_of_injective
      (IsFractionRing.injective (Polynomial K) (FractionRing (Polynomial K)))] at hpos
    exact hpos
  · simpa only [← F.eq_C_content_mul_primPart] using
      hassoc.mul_left (Polynomial.C F.content)

end
end HegemonCrypto.SmallWood.Mca38Published
