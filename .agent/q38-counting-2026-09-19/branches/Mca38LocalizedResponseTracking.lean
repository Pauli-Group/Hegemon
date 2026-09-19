import Mca38LocalizedNewtonStart

namespace HegemonCrypto.SmallWood.Mca38Published
noncomputable section
set_option autoImplicit false

variable {R S : Type*} [CommRing R] [CommRing S]

theorem newtonValid_map (ψ : R →+* S) (F : Polynomial R)
    (π : R) (m : ℕ) (s : R × R) (hs : NewtonValid F π m s) :
    NewtonValid (F.map ψ) (ψ π) m (ψ s.1, ψ s.2) := by
  constructor
  · simpa only [map_pow, Polynomial.eval_map_apply] using _root_.map_dvd ψ hs.1
  · simpa only [map_pow, Polynomial.derivative_map, Polynomial.eval_map_apply,
      map_sub, map_mul, map_one] using _root_.map_dvd ψ hs.2

def finiteNewtonResponse405 (F : Polynomial (Polynomial R))
    (s : Polynomial R × Polynomial R) : Polynomial R :=
  (newtonIterate F s 9).1 %ₘ (Polynomial.X ^ 406)

variable {K : Type*} [Field K]

set_option maxRecDepth 20000 in
/-- Root tracking after an actual coefficient-ring homomorphism. In the
application R is a finite localization, not the rational-function field. -/
theorem specialized_response_eq_finiteNewtonResponse405
    (ψ : R →+* K) (F : Polynomial (Polynomial R))
    (s : Polynomial R × Polynomial R)
    (hs : NewtonValid F Polynomial.X 1 s)
    (P : Polynomial K) (hP : P.natDegree ≤ 405)
    (hroot : (F.map (Polynomial.mapRingHom ψ)).eval P = 0)
    (hconstant : P.eval 0 = ψ (s.1.eval 0)) :
    P = (finiteNewtonResponse405 F s).map ψ := by
  let φ : Polynomial R →+* Polynomial K := Polynomial.mapRingHom ψ
  have hs' : NewtonValid (F.map φ) Polynomial.X 1 (φ s.1, φ s.2) := by
    simpa only [φ, Polynomial.coe_mapRingHom, Polynomial.map_X] using
      newtonValid_map φ F Polynomial.X 1 s hs
  have hclose : Polynomial.X ∣ P - φ s.1 := by
    rw [Polynomial.X_dvd_iff, Polynomial.coeff_zero_eq_eval_zero,
      Polynomial.eval_sub]
    change P.eval 0 - (s.1.map ψ).eval 0 = 0
    rw [Polynomial.eval_zero_map, hconstant, sub_self]
  have htrack := newtonIterate_tracks_root (F.map φ) Polynomial.X
    (φ s.1, φ s.2) hs' P hroot hclose 9
  have htrackMapped :
      (newtonIterate (F.map φ) (φ s.1, φ s.2) 9).1 =
        (newtonIterate F s 9).1.map ψ := by
    simpa only [φ, Polynomial.coe_mapRingHom] using
      congrArg Prod.fst (newtonIterate_map φ F s 9)
  rw [htrackMapped] at htrack
  have h406 : (Polynomial.X ^ 406 : Polynomial K) ∣
      P - (newtonIterate F s 9).1.map ψ := by
    exact dvd_trans (pow_dvd_pow Polynomial.X (by decide : 406 ≤ 512)) htrack
  have hmod := Polynomial.modByMonic_eq_of_dvd_sub
    (Polynomial.monic_X_pow 406) h406
  have hPmod : P %ₘ (Polynomial.X ^ 406) = P := by
    apply (Polynomial.modByMonic_eq_self_iff (Polynomial.monic_X_pow 406)).mpr
    calc
      P.degree ≤ (405 : WithBot ℕ) := Polynomial.degree_le_of_natDegree_le hP
      _ < (Polynomial.X ^ 406 : Polynomial K).degree := by
        rw [Polynomial.degree_X_pow]
        norm_num
  rw [hPmod] at hmod
  rw [finiteNewtonResponse405, Polynomial.map_modByMonic ψ
    (Polynomial.monic_X_pow 406), Polynomial.map_pow, Polynomial.map_X]
  exact hmod

/-- The concrete finite-localization map sends the adjoined starting root
to the selected specialized root t. -/
theorem finiteFactorSpecialization_localizedRoot
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K)) (z t : K)
    (hH : H.eval₂ (Polynomial.evalRingHom z) t = 0)
    (hd : (coefficientOrigin F).derivative.eval₂ (Polynomial.evalRingHom z) t ≠ 0) :
    finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd
      (localizedRoot F H) = t := by
  have h := finiteFactorSpecialization_numerator H (coefficientOrigin F).derivative
    Polynomial.X z t hH hd
  simpa only [AdjoinRoot.mk_X, Polynomial.eval₂_X, localizedRoot] using h

def actualLocalizedNewtonPolynomial
    (F : Polynomial (Polynomial R)) (H : Polynomial R) :
    Polynomial (Polynomial (NewtonFactorLocalization F H)) :=
  F.map (Polynomial.mapRingHom (localizedCoefficientMap F H))

def actualLocalizedNewtonState
    (F : Polynomial (Polynomial R)) (H : Polynomial R) :
    Polynomial (NewtonFactorLocalization F H) × Polynomial (NewtonFactorLocalization F H) :=
  (Polynomial.C (localizedRoot F H),
    Polynomial.C (IsLocalization.Away.invSelf
      (S := NewtonFactorLocalization F H) (AdjoinRoot.mk H (coefficientOrigin F).derivative)))

/-- The actual quotient/localization construction supplies Newton validity;
the response-degree bound and genuine specialized root are the only response
conditions, together with its selected starting root t. -/
theorem actual_specialized_response_tracks_localized_newton
    (F : Polynomial (Polynomial (Polynomial K))) (H : Polynomial (Polynomial K))
    (hdiv : H ∣ coefficientOrigin F) (z t : K)
    (hH : H.eval₂ (Polynomial.evalRingHom z) t = 0)
    (hd : (coefficientOrigin F).derivative.eval₂ (Polynomial.evalRingHom z) t ≠ 0)
    (P : Polynomial K) (hP : P.natDegree ≤ 405)
    (hroot : ((actualLocalizedNewtonPolynomial F H).map (Polynomial.mapRingHom
      (finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd))).eval P = 0)
    (hconstant : P.eval 0 = t) :
    P = (finiteNewtonResponse405 (actualLocalizedNewtonPolynomial F H)
      (actualLocalizedNewtonState F H)).map
        (finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd) := by
  apply specialized_response_eq_finiteNewtonResponse405
    (finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd)
    (actualLocalizedNewtonPolynomial F H) (actualLocalizedNewtonState F H)
    (actual_localized_newton_start F H hdiv) P hP hroot
  change P.eval 0 =
    finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd
      ((Polynomial.C (localizedRoot F H)).eval 0)
  rw [Polynomial.eval_C, finiteFactorSpecialization_localizedRoot, hconstant]

end
end HegemonCrypto.SmallWood.Mca38Published
