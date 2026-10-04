import Mca38RbrPolynomialEndpoint
import Mathlib.RingTheory.Polynomial.UniqueFactorization
import Mathlib.Algebra.Polynomial.Bivariate
import Mathlib.Algebra.Polynomial.BigOperators

/-! Direct factor coverage for the actual triple-nested source polynomial.

The factorization is performed on `Tri = K[Z][X][Y]` itself, so no conversion
through an arbitrary MvPolynomial factor is required.  The three coordinate
ledgers are obtained by injective variable permutations and associated-product
degree equalities.
-/
namespace HegemonCrypto.SmallWood.Mca38NestedFactorCoverage
open scoped BigOperators
noncomputable section
set_option autoImplicit false

variable {K : Type*} [Field K]
abbrev Tri := Polynomial (Polynomial (Polynomial K))

def xView : Polynomial (Polynomial (Polynomial K)) →+* Polynomial (Polynomial (Polynomial K)) :=
  (Polynomial.Bivariate.swap (R := Polynomial K)).toRingHom

def zView : Polynomial (Polynomial (Polynomial K)) →+* Polynomial (Polynomial (Polynomial K)) :=
  (Polynomial.Bivariate.swap (R := Polynomial K)).toRingHom.comp
    (Polynomial.mapRingHom (Polynomial.Bivariate.swap (R := K)).toRingHom)

@[irreducible] noncomputable def factors (F : Polynomial (Polynomial (Polynomial K))) :
    Multiset (Polynomial (Polynomial (Polynomial K))) :=
  by
    classical
    exact if h : F = 0 then 0 else Classical.choose (WfDvdMonoid.exists_factors F h)

theorem factors_spec {F : Tri (K := K)} (hF : F ≠ 0) :
    (∀ H ∈ factors F, Irreducible H) ∧ Associated (factors F).prod F := by
  simpa only [factors, dif_neg hF] using
    Classical.choose_spec (WfDvdMonoid.exists_factors F hF)

theorem factors_irreducible {F : Tri (K := K)} :
    ∀ H ∈ factors F, Irreducible H := by
  intro H hH
  by_cases hF : F = 0
  · subst F
    simp [factors] at hH
  · exact (factors_spec hF).1 H hH

theorem factors_nonzero {F H : Tri (K := K)} (hH : H ∈ factors F) : H ≠ 0 := by
  exact (factors_irreducible H hH).ne_zero

theorem factor_product_associated {F : Tri (K := K)} (hF : F ≠ 0) :
    Associated (factors F).prod F :=
  (factors_spec hF).2

theorem xView_injective : Function.Injective (xView (K := K)) := by
  exact (Polynomial.Bivariate.swap (R := Polynomial K)).injective

theorem zView_injective : Function.Injective (zView (K := K)) := by
  intro F G h
  apply Polynomial.map_injective _ (Polynomial.Bivariate.swap (R := K)).injective
  apply (Polynomial.Bivariate.swap (R := Polynomial K)).injective
  exact h

theorem ringHom_multiset_prod {R : Type*} [CommRing R]
    (φ : Tri (K := K) →+* R) (fs : Multiset (Tri (K := K))) :
    φ fs.prod = (fs.map (fun H => φ H)).prod := by
  induction fs using Multiset.induction_on with
  | empty => simp
  | cons H fs ih =>
    simp only [Multiset.prod_cons, Multiset.map_cons, map_mul, ih]

theorem embedding_degree_ledger
    (F : Tri (K := K)) (hF : F ≠ 0)
    (φ : Tri (K := K) →+* Tri (K := K)) (injective : Function.Injective φ) :
    ((factors F).map (fun H => (φ H).natDegree)).sum = (φ F).natDegree := by
  have associated : Associated (φ ((factors F).prod)) (φ F) :=
    (factor_product_associated hF).map φ
  have productMap : φ ((factors F).prod) =
      ((factors F).map (fun H => φ H)).prod :=
    ringHom_multiset_prod (K := K) (R := Tri (K := K)) φ (factors F)
  have associated' : Associated ((factors F).map (fun H => φ H)).prod (φ F) := by
    exact productMap ▸ associated
  have nonzero : (0 : Tri (K := K)) ∉ (factors F).map φ := by
    intro member
    obtain ⟨H, member, zero⟩ := Multiset.mem_map.mp member
    exact factors_nonzero member (injective (zero.trans (map_zero φ).symm))
  calc
    _ = (((factors F).map φ).map Polynomial.natDegree).sum := by
      rw [Multiset.map_map]
      rfl
    _ = (((factors F).map φ).prod).natDegree :=
      (Polynomial.natDegree_multiset_prod _ nonzero).symm
    _ = _ := Polynomial.natDegree_eq_of_degree_eq
      (Polynomial.degree_eq_degree_of_associated associated')

theorem degree_ledger (F : Tri (K := K)) (hF : F ≠ 0) :
    ((factors F).map Polynomial.natDegree).sum = F.natDegree ∧
    ((factors F).map (fun H => (xView H).natDegree)).sum = (xView F).natDegree ∧
    ((factors F).map (fun H => (zView H).natDegree)).sum = (zView F).natDegree := by
  exact ⟨embedding_degree_ledger F hF (RingHom.id _) Function.injective_id,
    embedding_degree_ledger F hF xView xView_injective,
    embedding_degree_ledger F hF zView zView_injective⟩

def specializePoly (z : K) (P : Polynomial K) :
    Polynomial (Polynomial (Polynomial K)) →+* Polynomial K :=
  (Polynomial.evalRingHom P).comp
    (Polynomial.mapRingHom (Polynomial.mapRingHom (Polynomial.evalRingHom z)))

theorem specialize_trivariateNested
    (c : HegemonCrypto.SmallWood.Mca38RoundByRoundInterpolation.CoefficientIndex → K)
    (z : K) (P : Polynomial K) :
    specializePoly z P
        (HegemonCrypto.SmallWood.Mca38RoundByRound.trivariateNested c) =
      HegemonCrypto.SmallWood.Mca38RoundByRound.specializedInterpolant c z P := by
  change
    ((HegemonCrypto.SmallWood.Mca38RoundByRound.trivariateNested c).map
      (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval P = _
  rw [HegemonCrypto.SmallWood.Mca38RoundByRound.trivariateNested_specialize_Z]
  exact HegemonCrypto.SmallWood.Mca38RoundByRound.nestedPolynomial_specialization_identity c z P

theorem mapped_factor_product_zero
    (F : Tri (K := K)) (hF : F ≠ 0) (z : K) (P : Polynomial K)
    (hzero : specializePoly z P F = 0) :
    ((factors F).map (fun H => specializePoly z P H)).prod = 0 := by
  have ha := (factor_product_associated hF).map (specializePoly z P)
  have zero := ha.eq_zero_iff.mpr hzero
  rw [ringHom_multiset_prod (specializePoly z P) (factors F)] at zero
  exact zero

theorem specialization_factor_coverage
    (F : Tri (K := K)) (hF : F ≠ 0) (z : K) (P : Polynomial K)
    (hzero : specializePoly z P F = 0) :
    ∃ H ∈ factors F, specializePoly z P H = 0 := by
  have hp := mapped_factor_product_zero F hF z P hzero
  by_contra hnone
  push Not at hnone
  have hne : ((factors F).map (fun H => specializePoly z P H)).prod ≠ 0 := by
    apply Multiset.prod_ne_zero
    intro member
    obtain ⟨H, hH, hzero⟩ := Multiset.mem_map.mp member
    exact (hnone H hH) hzero
  exact hne hp

theorem rbr_specialization_factor_coverage
    (c : HegemonCrypto.SmallWood.Mca38RoundByRoundInterpolation.CoefficientIndex → K)
    (hc : c ≠ 0) (z : K) (P : Polynomial K)
    (hzero : HegemonCrypto.SmallWood.Mca38RoundByRound.specializedInterpolant c z P = 0) :
    ∃ H ∈ factors
        (HegemonCrypto.SmallWood.Mca38RoundByRound.trivariateNested c),
      specializePoly z P H = 0 := by
  apply specialization_factor_coverage
    (HegemonCrypto.SmallWood.Mca38RoundByRound.trivariateNested c)
    (HegemonCrypto.SmallWood.Mca38RoundByRound.trivariateNested_ne_zero c hc)
  rw [specialize_trivariateNested]
  exact hzero

end
end HegemonCrypto.SmallWood.Mca38NestedFactorCoverage
