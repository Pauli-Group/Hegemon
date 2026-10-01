import Mca38ActualRootSourceHeight

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {K : Type*} [Field K]

set_option maxRecDepth 40000 in
/-- A concrete common numerator for the actual degree405 localized Newton
response. All shifted-coefficient, derivative-unit, constant-root, and finite
approximation premises have been discharged for the constructed objects. -/
theorem actual_full_newton_numerator
    (F : Polynomial (Polynomial (Polynomial K))) (H : Polynomial (Polynomial K))
    [Nontrivial (NewtonFactorLocalization F H)]
    (m Z : ℕ) (hmpos : 0 < m) (hm : F.natDegree ≤ m)
    (hF : ∀ j i, ((F.coeff j).coeff i).natDegree ≤ Z)
    (hdiv : H ∣ coefficientOrigin F) :
    ∃ Q : Polynomial (Polynomial (Polynomial K)),
      (∀ i, (Q.coeff i).natDegree ≤ 809*m) ∧
      (∀ i, (coefficientVariableSwap (Q.coeff i)).natDegree ≤ 809*Z) ∧
      Q.map (actualRootSourceMap F H) =
        Polynomial.C (actualRootSourceMap F H (coefficientOrigin F).derivative ^ 809) *
          finiteNewtonResponse405 (actualLocalizedNewtonPolynomial F H)
            (actualLocalizedNewtonState F H) := by
  let G := actualRootSource F
  let d := ((henselRootShift G Polynomial.X).coeff 1).coeff 0
  have hT := actualRootSource_shift_T_height F m hm
  have hZ := actualRootSource_shift_Z_height F m Z hm hF
  have hcT : (Polynomial.X : Polynomial (Polynomial K)).natDegree +
      (2*405-1)*d.natDegree ≤ (2*405-1)*m := by
    calc
      _ ≤ 1+809*(m-1) := Nat.add_le_add (by simp)
        (Nat.mul_le_mul_left 809 (hT 1 0))
      _ ≤ 809*m := constant_root_common_denominator_budget m 809 hmpos (by decide)
  have hcZ : (coefficientVariableSwap (Polynomial.X : Polynomial (Polynomial K))).natDegree +
      (2*405-1)*(coefficientVariableSwap d).natDegree ≤ (2*405-1)*Z := by
    rw [coefficientVariableSwap_X, Polynomial.natDegree_C, zero_add]
    exact Nat.mul_le_mul_left 809 (hZ 1 0)
  have hp := actualRootSource_response_properties F H hdiv
  obtain ⟨Q, hQT, hQZ, hQ⟩ := exists_full_hensel_numerator coefficientVariableSwap
    (actualRootSourceMap F H) G Polynomial.X
    (finiteNewtonResponse405 (actualLocalizedNewtonPolynomial F H) (actualLocalizedNewtonState F H))
    m Z 405
    (fun j i => (hT j i).trans (Nat.sub_le m j)) hZ
    (actualRootSource_derivative_isUnit F H) hcT hcZ hp.1 hp.2.1 hp.2.2
  refine ⟨Q, hQT, hQZ, ?_⟩
  simpa only [G, actualRootSource_derivative] using hQ

end
end HegemonCrypto.SmallWood.Mca38Published
