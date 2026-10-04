import Mca38ActualResidualNorm
import Mca38FiniteFactorLocalization

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {K L : Type*} [Field K] [Field L]

theorem quotientBaseMap_mk (H B : Polynomial (Polynomial K)) (φ : Polynomial K →+* L) :
    AdjoinRoot.map φ H (H.map φ) (dvd_refl _ ) (AdjoinRoot.mk H B) =
      AdjoinRoot.mk (H.map φ) (B.map φ) := by
  rw [AdjoinRoot.map, AdjoinRoot.lift_mk]
  rw [← Polynomial.eval₂_map, ← AdjoinRoot.algebraMap_eq,
    ← Polynomial.aeval_def, AdjoinRoot.aeval_eq]

def finiteFactorGenericMap (H d : Polynomial (Polynomial K)) (φ : Polynomial K →+* L)
    [Fact (Irreducible (H.map φ))]
    (hd : AdjoinRoot.mk (H.map φ) (d.map φ) ≠ 0) :
    FiniteFactorLocalization H d →+* AdjoinRoot (H.map φ) :=
  IsLocalization.Away.lift (AdjoinRoot.mk H d)
    (show IsUnit ((AdjoinRoot.map φ H (H.map φ) (dvd_refl _)) (AdjoinRoot.mk H d)) from by
      rw [quotientBaseMap_mk]
      exact isUnit_iff_ne_zero.mpr hd)

theorem finiteFactorGenericMap_numerator (H d B : Polynomial (Polynomial K))
    (φ : Polynomial K →+* L) [Fact (Irreducible (H.map φ))]
    (hd : AdjoinRoot.mk (H.map φ) (d.map φ) ≠ 0) :
    finiteFactorGenericMap H d φ hd
      (algebraMap (AdjoinRoot H) (FiniteFactorLocalization H d) (AdjoinRoot.mk H B)) =
      AdjoinRoot.mk (H.map φ) (B.map φ) := by
  rw [finiteFactorGenericMap, IsLocalization.Away.lift_eq, quotientBaseMap_mk]

/-- Select an actually nonzero coefficient of the generic residual, then
use its actual cleared numerator in the resultant. Neither the obstruction
polynomial, its nonvanishing, nor its root count is assumed. -/
theorem localized_cleared_residual_exception_count
    (H d : Polynomial (Polynomial K)) (φ : Polynomial K →+* L)
    (hinj : Function.Injective φ) [Fact (Irreducible (H.map φ))]
    (hd : AdjoinRoot.mk (H.map φ) (d.map φ) ≠ 0)
    (B : Polynomial (Polynomial (Polynomial K)))
    (r : Polynomial (FiniteFactorLocalization H d)) (e DT DZ DH : ℕ)
    (hclear : B.map ((algebraMap (AdjoinRoot H) (FiniteFactorLocalization H d)).comp
        (AdjoinRoot.mk H)) =
      Polynomial.C ((algebraMap (AdjoinRoot H) (FiniteFactorLocalization H d)
        (AdjoinRoot.mk H d)) ^ e) * r)
    (hgeneric : r.map (finiteFactorGenericMap H d φ hd) ≠ 0)
    (hBT : ∀ i, (B.coeff i).natDegree ≤ DT)
    (hBZ : ∀ i j, ((B.coeff i).coeff j).natDegree ≤ DZ)
    (hH : ∀ j, (H.coeff j).natDegree ≤ DH)
    (labels : Finset K)
    (hlabels : ∀ z ∈ labels, ∃ t : K,
      ∃ hroot : H.eval₂ (Polynomial.evalRingHom z) t = 0,
      ∃ hden : d.eval₂ (Polynomial.evalRingHom z) t ≠ 0,
      r.map (finiteFactorSpecialization H d z t hroot hden) = 0) :
    labels.card ≤ H.natDegree * DZ + DT * DH := by
  classical
  have hex : ∃ i, (r.map (finiteFactorGenericMap H d φ hd)).coeff i ≠ 0 := by
    by_contra! h
    apply hgeneric
    ext i
    simpa using h i
  obtain ⟨i, hi⟩ := hex
  have hcoeff : algebraMap (AdjoinRoot H) (FiniteFactorLocalization H d)
      (AdjoinRoot.mk H (B.coeff i)) =
      (algebraMap (AdjoinRoot H) (FiniteFactorLocalization H d)
        (AdjoinRoot.mk H d)) ^ e * r.coeff i := by
    have hc := congrArg (fun p => p.coeff i) hclear
    simpa only [Polynomial.coeff_map, RingHom.comp_apply, Polynomial.coeff_C_mul] using hc
  have hn : AdjoinRoot.mk (H.map φ) ((B.coeff i).map φ) ≠ 0 := by
    have hc := congrArg (finiteFactorGenericMap H d φ hd) hcoeff
    rw [finiteFactorGenericMap_numerator, map_mul, map_pow,
      finiteFactorGenericMap_numerator] at hc
    rw [hc]
    exact mul_ne_zero (pow_ne_zero _ hd) (by simpa only [Polynomial.coeff_map] using hi)
  have hc := actual_quotient_residual_exception_count H (B.coeff i) φ hinj
    (Fact.out : Irreducible (H.map φ)) hn DH DZ hH (hBZ i) labels (by
      intro z hz
      obtain ⟨t, hroot, hden, hr⟩ := hlabels z hz
      refine ⟨t, hroot, localized_residual_zero_forces_numerator_zero H d (B.coeff i)
        (r.coeff i) e hcoeff z t hroot hden ?_⟩
      have hri := congrArg (fun p => p.coeff i) hr
      simpa only [Polynomial.coeff_map, Polynomial.coeff_zero] using hri)
  exact hc.trans (Nat.add_le_add_left (Nat.mul_le_mul_right DH (hBT i)) _)

end
end HegemonCrypto.SmallWood.Mca38Published
