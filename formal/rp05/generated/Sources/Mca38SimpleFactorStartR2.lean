import Mca38HenselTransferR2
import Mathlib.FieldTheory.Separable
import Mathlib.RingTheory.AdjoinRoot
import Mathlib.RingTheory.Polynomial.UniqueFactorization
import Lean.Elab.Tactic.Omega

/-! Construct a normalized starting factor, its genuine algebraic quotient,
and an explicit finite Newton start from a separable specialization.
Uniform choice of the specialization remains a separate obligation. -/

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false

variable {K : Type*} [Field K]

noncomputable def shiftCoefficientVariable
    (f : Polynomial (Polynomial K)) (x : K) : Polynomial (Polynomial K) :=
  f.map (Polynomial.taylorAlgHom x).toRingHom

noncomputable def specializeCoefficientVariable
    (f : Polynomial (Polynomial K)) (x : K) : Polynomial K :=
  f.map (Polynomial.evalRingHom x)

theorem residue_shiftCoefficientVariable
    (f : Polynomial (Polynomial K)) (x : K) :
    residuePolynomial (shiftCoefficientVariable f x) =
      specializeCoefficientVariable f x := by
  ext j
  simp [residuePolynomial, shiftCoefficientVariable, specializeCoefficientVariable,
    Polynomial.coeff_map, Polynomial.taylor_eval]

theorem residue_map_coefficients {L : Type*} [Field L]
    (φ : K →+* L) (f : Polynomial (Polynomial K)) :
    residuePolynomial (f.map (Polynomial.mapRingHom φ)) =
      (residuePolynomial f).map φ := by
  ext j
  simp only [residuePolynomial, Polynomial.coeff_map, Polynomial.coe_mapRingHom,
    Polynomial.coe_evalRingHom]
  simpa only [map_zero] using
    Polynomial.eval_map_apply (f := φ) (p := f.coeff j) (0 : K)

/-- The irreducible factor and Newton witness are outputs, not assumptions.
The quotient is `AdjoinRoot H`, so its algebraic root is tied to the actual
monic factor H of the specialized polynomial. -/
theorem exists_simple_factor_newton_start
    (f : Polynomial (Polynomial K)) (x : K)
    (hsep : (specializeCoefficientVariable f x).Separable)
    (hpositive : 0 < (specializeCoefficientVariable f x).natDegree) :
    ∃ H : Polynomial K, H.Monic ∧ Irreducible H ∧
      H ∣ specializeCoefficientVariable f x ∧ H.Separable ∧
      ∃ b : AdjoinRoot H,
        NewtonValid
          ((shiftCoefficientVariable f x).map
            (Polynomial.mapRingHom (AdjoinRoot.of H)))
          Polynomial.X 1 (Polynomial.C (AdjoinRoot.root H), Polynomial.C b) := by
  have hunit : ¬ IsUnit (specializeCoefficientVariable f x) := by
    intro hu
    have hd := Polynomial.natDegree_eq_zero_of_isUnit hu
    omega
  obtain ⟨H, hmonic, hirred, hdiv⟩ :=
    Polynomial.exists_monic_irreducible_factor (specializeCoefficientVariable f x) hunit
  letI : Fact (Irreducible H) := ⟨hirred⟩
  let φ : K →+* AdjoinRoot H := AdjoinRoot.of H
  let F : Polynomial (Polynomial (AdjoinRoot H)) :=
    (shiftCoefficientVariable f x).map (Polynomial.mapRingHom φ)
  have hres : residuePolynomial F = (specializeCoefficientVariable f x).map φ := by
    change residuePolynomial ((shiftCoefficientVariable f x).map
      (Polynomial.mapRingHom φ)) = (specializeCoefficientVariable f x).map φ
    rw [residue_map_coefficients, residue_shiftCoefficientVariable]
  have hroot₂ : (specializeCoefficientVariable f x).eval₂ φ (AdjoinRoot.root H) = 0 := by
    obtain ⟨q, hq⟩ := hdiv
    rw [hq, Polynomial.eval₂_mul]
    have hz : H.eval₂ φ (AdjoinRoot.root H) = 0 := AdjoinRoot.eval₂_root H
    rw [hz, zero_mul]
  have hroot : (residuePolynomial F).eval (AdjoinRoot.root H) = 0 := by
    rw [hres, Polynomial.eval_map]
    exact hroot₂
  have hderivative : (residuePolynomial F).derivative.eval (AdjoinRoot.root H) ≠ 0 := by
    rw [hres, Polynomial.derivative_map, Polynomial.eval_map]
    exact hsep.eval₂_derivative_ne_zero φ hroot₂
  refine ⟨H, hmonic, hirred, hdiv, hsep.of_dvd hdiv,
    ((residuePolynomial F).derivative.eval (AdjoinRoot.root H))⁻¹, ?_⟩
  exact constant_start_valid F (AdjoinRoot.root H) hroot hderivative

end HegemonCrypto.SmallWood.Mca38Published
