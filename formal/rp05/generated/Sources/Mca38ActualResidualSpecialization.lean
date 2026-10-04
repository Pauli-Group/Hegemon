import Mca38LocalizedSourceSpecialization

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {K : Type*} [Field K]

/-- Every genuine specialized degree405 response annihilates the complete
actual localized Newton residual after specialization. This provides the
vanishing premise for every coefficient of its cleared numerator. -/
theorem actual_newton_residual_specializes_zero
    (F : Polynomial (Polynomial (Polynomial K))) (H : Polynomial (Polynomial K))
    (hdiv : H ∣ coefficientOrigin F) (z t : K)
    (hH : H.eval₂ (Polynomial.evalRingHom z) t = 0)
    (hd : (coefficientOrigin F).derivative.eval₂ (Polynomial.evalRingHom z) t ≠ 0)
    (P : Polynomial K) (hP : P.natDegree ≤ 405)
    (hroot : (F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval P = 0)
    (hconstant : P.eval 0 = t) :
    ((actualLocalizedNewtonPolynomial F H).eval
      (finiteNewtonResponse405 (actualLocalizedNewtonPolynomial F H)
        (actualLocalizedNewtonState F H))).map
      (finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd) = 0 := by
  have ht := actual_source_response_tracks_localized_newton F H hdiv z t hH hd
    P hP hroot hconstant
  have he := Polynomial.eval_map_apply
    (p := actualLocalizedNewtonPolynomial F H)
    (f := Polynomial.mapRingHom
      (finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd))
    (finiteNewtonResponse405 (actualLocalizedNewtonPolynomial F H)
      (actualLocalizedNewtonState F H))
  change _ = (Polynomial.mapRingHom
    (finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd)) _ at he
  change (Polynomial.mapRingHom
    (finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd)) _ = 0
  calc
    (Polynomial.mapRingHom
        (finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd))
        (Polynomial.eval (finiteNewtonResponse405
          (actualLocalizedNewtonPolynomial F H)
          (actualLocalizedNewtonState F H)) (actualLocalizedNewtonPolynomial F H)) =
      (Polynomial.eval
        ((Polynomial.mapRingHom
          (finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd))
          (finiteNewtonResponse405 (actualLocalizedNewtonPolynomial F H)
            (actualLocalizedNewtonState F H)))
        ((actualLocalizedNewtonPolynomial F H).map
          (Polynomial.mapRingHom
            (finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd)))) := by
      exact he.symm
    _ = (F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval
        ((finiteNewtonResponse405 (actualLocalizedNewtonPolynomial F H)
          (actualLocalizedNewtonState F H)).map
          (finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd)) := by
      rw [actualLocalizedNewtonPolynomial_specializes_to_source]
      rfl
    _ = (F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval P := by
      rw [← ht]
    _ = 0 := hroot

end
end HegemonCrypto.SmallWood.Mca38Published
