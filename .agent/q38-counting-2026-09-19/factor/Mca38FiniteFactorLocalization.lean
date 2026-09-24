import Mathlib.RingTheory.AdjoinRoot
import Mathlib.RingTheory.Localization.Away.Basic

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {K : Type*} [Field K]

/-- A finite localization of the actual quotient by H, inverting one
explicit denominator representative d. No map from K(Z) to K is used. -/
abbrev FiniteFactorLocalization (H d : Polynomial (Polynomial K)) :=
  Localization.Away (AdjoinRoot.mk H d)

def finiteFactorSpecialization (H d : Polynomial (Polynomial K)) (z t : K)
    (hH : H.eval₂ (Polynomial.evalRingHom z) t = 0)
    (hd : d.eval₂ (Polynomial.evalRingHom z) t ≠ 0) :
    FiniteFactorLocalization H d →+* K :=
  IsLocalization.Away.lift (AdjoinRoot.mk H d)
    (show IsUnit ((AdjoinRoot.lift (Polynomial.evalRingHom z) t hH) (AdjoinRoot.mk H d)) from by
      rw [AdjoinRoot.lift_mk]
      exact isUnit_iff_ne_zero.mpr hd)

theorem finiteFactorSpecialization_numerator
    (H d B : Polynomial (Polynomial K)) (z t : K)
    (hH : H.eval₂ (Polynomial.evalRingHom z) t = 0)
    (hd : d.eval₂ (Polynomial.evalRingHom z) t ≠ 0) :
    finiteFactorSpecialization H d z t hH hd
      (algebraMap (AdjoinRoot H) (FiniteFactorLocalization H d) (AdjoinRoot.mk H B)) =
        B.eval₂ (Polynomial.evalRingHom z) t := by
  rw [finiteFactorSpecialization, IsLocalization.Away.lift_eq, AdjoinRoot.lift_mk]

/-- A cleared actual localized residual specializes to the ordinary
polynomial numerator. This is the interface for applying the actual
resultant obstruction to finite Newton residual coefficients. -/
theorem localized_residual_zero_forces_numerator_zero
    (H d B : Polynomial (Polynomial K)) (r : FiniteFactorLocalization H d)
    (e : ℕ)
    (hclear : algebraMap (AdjoinRoot H) (FiniteFactorLocalization H d) (AdjoinRoot.mk H B) =
      (algebraMap (AdjoinRoot H) (FiniteFactorLocalization H d) (AdjoinRoot.mk H d)) ^ e * r)
    (z t : K) (hH : H.eval₂ (Polynomial.evalRingHom z) t = 0)
    (hd : d.eval₂ (Polynomial.evalRingHom z) t ≠ 0)
    (hzero : finiteFactorSpecialization H d z t hH hd r = 0) :
    B.eval₂ (Polynomial.evalRingHom z) t = 0 := by
  have h := congrArg (finiteFactorSpecialization H d z t hH hd) hclear
  rw [finiteFactorSpecialization_numerator, map_mul, map_pow, hzero, mul_zero] at h
  exact h

end
end HegemonCrypto.SmallWood.Mca38Published
