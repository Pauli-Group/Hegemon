import Mca38FullNumeratorEndpoint
import Mca38LocalizedNewtonTruncation

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {R : Type*} [CommRing R]

/-- Insert the indeterminate T representing the starting algebraic root. -/
def actualRootSource (F : Polynomial (Polynomial R)) :
    Polynomial (Polynomial (Polynomial R)) :=
  F.map (Polynomial.mapRingHom Polynomial.C)

def actualRootSourceMap (F : Polynomial (Polynomial R)) (H : Polynomial R) :
    Polynomial R →+* NewtonFactorLocalization F H :=
  (algebraMap (AdjoinRoot H) (NewtonFactorLocalization F H)).comp (AdjoinRoot.mk H)

theorem actualRootSourceMap_C (F : Polynomial (Polynomial R)) (H : Polynomial R) (r : R) :
    actualRootSourceMap F H (Polynomial.C r) = localizedCoefficientMap F H r := rfl

theorem actualRootSourceMap_X (F : Polynomial (Polynomial R)) (H : Polynomial R) :
    actualRootSourceMap F H Polynomial.X = localizedRoot F H := rfl

theorem actualRootSource_map (F : Polynomial (Polynomial R)) (H : Polynomial R) :
    (actualRootSource F).map (Polynomial.mapRingHom (actualRootSourceMap F H)) =
      actualLocalizedNewtonPolynomial F H := by
  ext j i
  simp only [actualRootSource, actualLocalizedNewtonPolynomial, Polynomial.coeff_map,
    Polynomial.coe_mapRingHom, actualRootSourceMap_C]

/-- The derivative representative produced by the actual source shift is
exactly the polynomial inverted in the finite localization. -/
theorem actualRootSource_derivative (F : Polynomial (Polynomial R)) :
    ((henselRootShift (actualRootSource F) Polynomial.X).coeff 1).coeff 0 =
      (coefficientOrigin F).derivative := by
  rw [henselRootShift_derivative_origin, Polynomial.coeff_zero_eq_eval_zero,
    eval_constant_coefficientOrigin]
  have hd : coefficientOrigin (actualRootSource F).derivative =
      (coefficientOrigin (actualRootSource F)).derivative := by
    simp only [coefficientOrigin, Polynomial.derivative_map]
  rw [hd]
  have ho : coefficientOrigin (actualRootSource F) =
      (coefficientOrigin F).map Polynomial.C := coefficientOrigin_map Polynomial.C F
  rw [ho, Polynomial.derivative_map, Polynomial.eval_map]
  change (coefficientOrigin F).derivative.comp Polynomial.X = _
  exact Polynomial.comp_X

theorem actualRootSource_derivative_isUnit
    (F : Polynomial (Polynomial R)) (H : Polynomial R) :
    IsUnit (actualRootSourceMap F H
      (((henselRootShift (actualRootSource F) Polynomial.X).coeff 1).coeff 0)) := by
  rw [actualRootSource_derivative]
  exact IsLocalization.Away.algebraMap_isUnit (AdjoinRoot.mk H (coefficientOrigin F).derivative)

/-- All finite-Hensel response premises are obtained from the constructed
localized Newton iterate, rather than supplied as approximation assumptions. -/
theorem actualRootSource_response_properties
    (F : Polynomial (Polynomial R)) (H : Polynomial R)
    [Nontrivial (NewtonFactorLocalization F H)] (hdiv : H ∣ coefficientOrigin F) :
    let p := finiteNewtonResponse405 (actualLocalizedNewtonPolynomial F H)
      (actualLocalizedNewtonState F H)
    p.natDegree ≤ 405 ∧
    p.coeff 0 = actualRootSourceMap F H Polynomial.X ∧
    Polynomial.X^406 ∣ ((actualRootSource F).map
      (Polynomial.mapRingHom (actualRootSourceMap F H))).eval p := by
  have hp := finiteNewtonResponse405_properties (actualLocalizedNewtonPolynomial F H)
    (actualLocalizedNewtonState F H) (actual_localized_newton_start F H hdiv)
  simpa only [actualRootSource_map, actualRootSourceMap_X, actualLocalizedNewtonState,
    Polynomial.coeff_C_zero] using hp

end
end HegemonCrypto.SmallWood.Mca38Published
