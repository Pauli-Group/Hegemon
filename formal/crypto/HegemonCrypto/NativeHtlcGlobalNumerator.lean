import Mca38ActualRootSourceHeight
import HegemonCrypto.NativeHtlcGlobalNewton

namespace HegemonCrypto.SmallWood.NativeHtlcGlobalNumerator
open HegemonCrypto.SmallWood.Mca38Published
open HegemonCrypto.SmallWood.NativeHtlcGlobalNewton
set_option autoImplicit false
noncomputable section

variable {K : Type*} [Field K]

/-- The actual source map and the new finite Newton iterate discharge the
three response premises used by the generic Hensel numerator theorem. -/
theorem actualRootSource_response_properties9933
    {R : Type*} [CommRing R]
    (F : Polynomial (Polynomial R)) (H : Polynomial R)
    [Nontrivial (NewtonFactorLocalization F H)] (hdiv : H ∣ coefficientOrigin F) :
    let p := finiteNewtonResponse9933 (actualLocalizedNewtonPolynomial F H)
      (actualLocalizedNewtonState F H)
    p.natDegree ≤ 9933 ∧
    p.coeff 0 = actualRootSourceMap F H Polynomial.X ∧
    Polynomial.X^9934 ∣ ((actualRootSource F).map
      (Polynomial.mapRingHom (actualRootSourceMap F H))).eval p := by
  have hp := finiteNewtonResponse9933_properties (actualLocalizedNewtonPolynomial F H)
    (actualLocalizedNewtonState F H) (actual_localized_newton_start F H hdiv)
  simpa only [actualRootSource_map, actualRootSourceMap_X, actualLocalizedNewtonState,
    Polynomial.coeff_C_zero] using hp



set_option maxRecDepth 200000 in
/-- A concrete common numerator for the actual degree9933 localized Newton
response. All shifted-coefficient, derivative-unit, constant-root, and finite
approximation premises have been discharged for the constructed objects. -/
theorem actual_full_newton_numerator9933
    (F : Polynomial (Polynomial (Polynomial K))) (H : Polynomial (Polynomial K))
    [Nontrivial (NewtonFactorLocalization F H)]
    (m Z : ℕ) (hmpos : 0 < m) (hm : F.natDegree ≤ m)
    (hF : ∀ j i, ((F.coeff j).coeff i).natDegree ≤ Z)
    (hdiv : H ∣ coefficientOrigin F) :
    ∃ Q : Polynomial (Polynomial (Polynomial K)),
      (∀ i, (Q.coeff i).natDegree ≤ 19865*m) ∧
      (∀ i, (coefficientVariableSwap (Q.coeff i)).natDegree ≤ 19865*Z) ∧
      Q.map (actualRootSourceMap F H) =
        Polynomial.C (actualRootSourceMap F H (coefficientOrigin F).derivative ^ 19865) *
          finiteNewtonResponse9933 (actualLocalizedNewtonPolynomial F H)
            (actualLocalizedNewtonState F H) := by
  let G := actualRootSource F
  let d := ((henselRootShift G Polynomial.X).coeff 1).coeff 0
  have hT := actualRootSource_shift_T_height F m hm
  have hZ := actualRootSource_shift_Z_height F m Z hm hF
  have hcT : (Polynomial.X : Polynomial (Polynomial K)).natDegree +
      (2*9933-1)*d.natDegree ≤ (2*9933-1)*m := by
    calc
      _ ≤ 1+19865*(m-1) := Nat.add_le_add (by simp)
        (Nat.mul_le_mul_left 19865 (hT 1 0))
      _ ≤ 19865*m := constant_root_common_denominator_budget m 19865 hmpos (by decide)
  have hcZ : (coefficientVariableSwap (Polynomial.X : Polynomial (Polynomial K))).natDegree +
      (2*9933-1)*(coefficientVariableSwap d).natDegree ≤ (2*9933-1)*Z := by
    rw [coefficientVariableSwap_X, Polynomial.natDegree_C, zero_add]
    exact Nat.mul_le_mul_left 19865 (hZ 1 0)
  have hp := actualRootSource_response_properties9933 F H hdiv
  obtain ⟨Q, hQT, hQZ, hQ⟩ := exists_full_hensel_numerator coefficientVariableSwap
    (actualRootSourceMap F H) G Polynomial.X
    (finiteNewtonResponse9933 (actualLocalizedNewtonPolynomial F H) (actualLocalizedNewtonState F H))
    m Z 9933
    (fun j i => (hT j i).trans (Nat.sub_le m j)) hZ
    (actualRootSource_derivative_isUnit F H) hcT hcZ hp.1 hp.2.1 hp.2.2
  refine ⟨Q, hQT, hQZ, ?_⟩
  simpa only [G, actualRootSource_derivative] using hQ

end
end HegemonCrypto.SmallWood.NativeHtlcGlobalNumerator
