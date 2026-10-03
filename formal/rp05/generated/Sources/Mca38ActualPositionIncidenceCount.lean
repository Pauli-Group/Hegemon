import Mca38ActualNonaffineBranchCount
import Mca38ActualResidualSpecialization

/-! A genuine source-response incidence, not a supplied obstruction.
The finite Newton branch specializes to the selected degree-405 response.
Its mismatch with one source line therefore vanishes at every agreeing label.
The actual common numerator and resultant supply the single-position count.
-/
namespace HegemonCrypto.SmallWood.Mca38ActualPositionIncidenceCount
open HegemonCrypto.SmallWood.Mca38Published
open HegemonCrypto.SmallWood.Mca38ActualNonaffineBranchCount
noncomputable section
set_option autoImplicit false
variable {K L : Type*} [Field K] [Field L]

def actualIncidenceResidue
    (F : Polynomial (Polynomial (Polynomial K))) (H : Polynomial (Polynomial K))
    (x u v : K) : NewtonFactorLocalization F H :=
  (finiteNewtonResponse405 (actualLocalizedNewtonPolynomial F H)
    (actualLocalizedNewtonState F H)).eval
      (actualRootSourceMap F H (Polynomial.C (Polynomial.C x))) -
    actualRootSourceMap F H (Polynomial.C (affineLine u v))

theorem actual_incidence_specializes_zero
    (F : Polynomial (Polynomial (Polynomial K))) (H : Polynomial (Polynomial K))
    (divides : H ∣ coefficientOrigin F) (z t x u v : K)
    (root : H.eval₂ (Polynomial.evalRingHom z) t = 0)
    (simple : (coefficientOrigin F).derivative.eval₂ (Polynomial.evalRingHom z) t ≠ 0)
    (P : Polynomial K) (degree : P.natDegree ≤ 405)
    (response : (F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval P = 0)
    (initial : P.eval 0 = t) (agreement : P.eval x = u + z * v) :
    finiteFactorSpecialization H (coefficientOrigin F).derivative z t root simple
      (actualIncidenceResidue F H x u v) = 0 := by
  let σ := finiteFactorSpecialization H (coefficientOrigin F).derivative z t root simple
  have point : σ (actualRootSourceMap F H (Polynomial.C (Polynomial.C x))) = x := by
    simp only [σ, actualRootSourceMap_C,
      finiteFactorSpecialization_localizedCoefficient, Polynomial.eval_C]
  have line : σ (actualRootSourceMap F H (Polynomial.C (affineLine u v))) =
      u + z * v := by
    simp only [σ, actualRootSourceMap_C,
      finiteFactorSpecialization_localizedCoefficient, affineLine,
      Polynomial.eval_add, Polynomial.eval_mul, Polynomial.eval_C, Polynomial.eval_X]
  have tracking := actual_source_response_tracks_localized_newton F H divides
    z t root simple P degree response initial
  change σ (actualIncidenceResidue F H x u v) = 0
  unfold actualIncidenceResidue
  rw [map_sub, ← Polynomial.eval_map_apply, point, ← tracking, line]
  exact sub_eq_zero.mpr agreement

/-- For every genuinely nonidentical branch/position pair, the label count is
the degree bound of its constructed resultant. Neither its existence nor its
nonvanishing is an extra premise. -/
theorem actual_position_label_count
    (F : Polynomial (Polynomial (Polynomial K))) (H : Polynomial (Polynomial K))
    (φ : Polynomial K →+* L) (injective : Function.Injective φ)
    [Fact (Irreducible (H.map φ))]
    (denominator : AdjoinRoot.mk (H.map φ) ((coefficientOrigin F).derivative.map φ) ≠ 0)
    (m Z DH : Nat) (positive : 0 < m) (degree : F.natDegree ≤ m)
    (sourceHeight : ∀ j i, ((F.coeff j).coeff i).natDegree ≤ Z)
    (factorHeight : ∀ j, (H.coeff j).natDegree ≤ DH)
    (divides : H ∣ coefficientOrigin F) (x u v : K)
    (nonidentical : finiteFactorGenericMap H (coefficientOrigin F).derivative φ denominator
      (actualIncidenceResidue F H x u v) ≠ 0)
    (labels : Finset K)
    (responses : ∀ z ∈ labels, ∃ t : K,
      H.eval₂ (Polynomial.evalRingHom z) t = 0 ∧
      (coefficientOrigin F).derivative.eval₂ (Polynomial.evalRingHom z) t ≠ 0 ∧
      ∃ P : Polynomial K, P.natDegree ≤ 405 ∧
        (F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval P = 0 ∧
        P.eval 0 = t ∧ P.eval x = u + z * v) :
    labels.card ≤ H.natDegree * (809 * Z + 1) + (809 * m) * DH := by
  letI : Nontrivial (NewtonFactorLocalization F H) :=
    (finiteFactorGenericMap H (coefficientOrigin F).derivative φ denominator).domain_nontrivial
  have derivativeHeight : (coefficientOrigin F).derivative.natDegree ≤ m := by
    have bound := (actualRootSource_shift_T_height F m degree 1 0).trans
      (Nat.sub_le m 1)
    rwa [actualRootSource_derivative] at bound
  have derivativeZHeight :
      (coefficientVariableSwap (coefficientOrigin F).derivative).natDegree ≤ Z := by
    have bound := actualRootSource_shift_Z_height F m Z degree sourceHeight 1 0
    rwa [actualRootSource_derivative] at bound
  obtain ⟨N, degreeT, degreeZ, cleared⟩ :=
    actual_incidence_numerator F H m Z positive degree sourceHeight divides
  apply localized_scalar_incidence_count H (coefficientOrigin F).derivative
    (branchIncidence N (coefficientOrigin F).derivative x u v) φ injective denominator
    (actualIncidenceResidue F H x u v) 809 (809 * m) (809 * Z + 1) DH
    (cleared x u v) nonidentical
    (branchIncidence_T_height N _ x u v m degreeT derivativeHeight)
    (fun j => (coefficient_natDegree_le_variableSwap _ j).trans
      (branchIncidence_Z_height N _ x u v Z degreeZ derivativeZHeight))
    factorHeight labels
  intro z member
  obtain ⟨t, root, simple, P, bounded, response, initial, agreement⟩ := responses z member
  exact ⟨t, root, simple, actual_incidence_specializes_zero F H divides z t x u v
    root simple P bounded response initial agreement⟩

end
end HegemonCrypto.SmallWood.Mca38ActualPositionIncidenceCount
