import Mca38LocalizedResponseTracking

namespace HegemonCrypto.SmallWood.Mca38Published
noncomputable section
set_option autoImplicit false
variable {K : Type*} [Field K]

theorem finiteFactorSpecialization_localizedCoefficient
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K)) (z t : K)
    (hH : H.eval₂ (Polynomial.evalRingHom z) t = 0)
    (hd : (coefficientOrigin F).derivative.eval₂ (Polynomial.evalRingHom z) t ≠ 0)
    (p : Polynomial K) :
    finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd
      (localizedCoefficientMap F H p) = p.eval z := by
  have h := finiteFactorSpecialization_numerator H (coefficientOrigin F).derivative
    (Polynomial.C p) z t hH hd
  simpa only [AdjoinRoot.mk_C, Polynomial.eval₂_C, localizedCoefficientMap,
    RingHom.comp_apply, Polynomial.coe_evalRingHom] using h

theorem actualLocalizedNewtonPolynomial_specializes_to_source
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K)) (z t : K)
    (hH : H.eval₂ (Polynomial.evalRingHom z) t = 0)
    (hd : (coefficientOrigin F).derivative.eval₂ (Polynomial.evalRingHom z) t ≠ 0) :
    (actualLocalizedNewtonPolynomial F H).map (Polynomial.mapRingHom
      (finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd)) =
      F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z)) := by
  ext j i
  simp only [actualLocalizedNewtonPolynomial, Polynomial.coeff_map,
    Polynomial.coe_mapRingHom, finiteFactorSpecialization_localizedCoefficient,
    Polynomial.coe_evalRingHom]

/-- Genuine roots of the specialized source polynomial are the mapped
truncated Newton response. All maps come from the finite quotient/localization. -/
theorem actual_source_response_tracks_localized_newton
    (F : Polynomial (Polynomial (Polynomial K))) (H : Polynomial (Polynomial K))
    (hdiv : H ∣ coefficientOrigin F) (z t : K)
    (hH : H.eval₂ (Polynomial.evalRingHom z) t = 0)
    (hd : (coefficientOrigin F).derivative.eval₂ (Polynomial.evalRingHom z) t ≠ 0)
    (P : Polynomial K) (hP : P.natDegree ≤ 405)
    (hroot : (F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval P = 0)
    (hconstant : P.eval 0 = t) :
    P = (finiteNewtonResponse405 (actualLocalizedNewtonPolynomial F H)
      (actualLocalizedNewtonState F H)).map
        (finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd) := by
  apply actual_specialized_response_tracks_localized_newton F H hdiv z t hH hd P hP
  · rw [actualLocalizedNewtonPolynomial_specializes_to_source]
    exact hroot
  · exact hconstant

end
end HegemonCrypto.SmallWood.Mca38Published
