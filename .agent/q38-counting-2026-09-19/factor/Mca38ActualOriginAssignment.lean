import Mca38OriginFactorCoverage
import Mca38TranslatedRegularOrigin

/-! Assign actual regular source responses to a finite primitive origin-factor
family.  The family and both additive degree ledgers are constructed, and the
selected response itself supplies the origin root; no root selector is assumed.
-/
namespace HegemonCrypto.SmallWood.Mca38ActualOriginAssignment
open HegemonCrypto.SmallWood.Mca38Published
open HegemonCrypto.SmallWood.Mca38NestedFactorCoverage
open HegemonCrypto.SmallWood.Mca38NestedFactorSeparability
open HegemonCrypto.SmallWood.Mca38NestedTranslation
open HegemonCrypto.SmallWood.Mca38TranslatedRegularOrigin
open HegemonCrypto.SmallWood.Mca38OriginFactorCoverage
noncomputable section
set_option autoImplicit false
variable {K : Type*} [Field K]

theorem response_supplies_origin_root
    (F : Polynomial (Polynomial (Polynomial K))) (z : K) (P : Polynomial K)
    (root : (F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval P = 0) :
    (coefficientOrigin F).eval₂ (Polynomial.evalRingHom z) (P.eval 0) = 0 := by
  have evaluated := Polynomial.eval_map_apply
    (p := F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z)))
    (f := Polynomial.evalRingHom (0 : K)) P
  rw [root, map_zero] at evaluated
  change (coefficientOrigin (F.map (Polynomial.mapRingHom
    (Polynomial.evalRingHom z)))).eval (P.eval 0) = 0 at evaluated
  rw [coefficientOrigin_map, Polynomial.eval_map] at evaluated
  exact evaluated

theorem translated_origin_Z_height
    (H : Polynomial (Polynomial (Polynomial K))) (x : K) :
    bivariateCoefficientHeight (translatedOrigin x H) ≤
      (HegemonCrypto.SmallWood.Mca38NestedFactorCoverage.zView H).natDegree := by
  apply bivariateCoefficientHeight_le_of_coeff_bound
  intro j
  have height := translateX_Z_coefficient_height x H j 0
  change (((translateX x H).coeff j).coeff 0).natDegree ≤
    (HegemonCrypto.SmallWood.Mca38NestedFactorCoverage.zView H).natDegree at height
  simpa only [translatedOrigin, coefficientOrigin, Polynomial.coeff_map,
    Polynomial.coe_evalRingHom, Polynomial.coeff_zero_eq_eval_zero] using height

/-- A single regular response label suffices to construct the origin family
for the source factor. It then covers every regular response label, with the
same shared Y/Z degree budgets. -/
theorem exists_actual_origin_assignment
    (H : Polynomial (Polynomial (Polynomial K))) (positive : 0 < H.natDegree)
    (x z₀ : K)
    (regular₀ : ((regularityObstruction H).eval (Polynomial.C x)).eval z₀ ≠ 0) :
    ∃ fs : Multiset (Polynomial (Polynomial K)),
      (∀ G ∈ fs, Irreducible G ∧ G.IsPrimitive ∧
        Irreducible (G.map (algebraMap (Polynomial K) (FractionRing (Polynomial K)))) ∧
        0 < G.natDegree ∧ G ∣ coefficientOrigin (translateX x H)) ∧
      (fs.map Polynomial.natDegree).sum = H.natDegree ∧
      (fs.map bivariateCoefficientHeight).sum ≤
        (HegemonCrypto.SmallWood.Mca38NestedFactorCoverage.zView H).natDegree ∧
      ∀ z : K, ((regularityObstruction H).eval (Polynomial.C x)).eval z ≠ 0 →
        ∀ P : Polynomial K, specializePoly z P H = 0 →
          ∃ G ∈ fs,
            G.eval₂ (Polynomial.evalRingHom z) (P.eval x) = 0 ∧
            (coefficientOrigin (translateX x H)).derivative.eval₂
              (Polynomial.evalRingHom z) (P.eval x) ≠ 0 := by
  have originNonzero : translatedOrigin x H ≠ 0 := by
    intro zero
    have leading := translated_origin_leading_coefficient_ne_zero H x z₀ regular₀
    simp only [zero, Polynomial.leadingCoeff_zero, Polynomial.eval_zero, ne_eq,
      not_true_eq_false] at leading
  obtain ⟨fs, irreducible, degreeY, degreeZ, coverage⟩ :=
    exists_primitive_origin_family (translatedOrigin x H) originNonzero
  refine ⟨fs, irreducible, ?_, degreeZ.trans (translated_origin_Z_height H x), ?_⟩
  · exact degreeY.trans (translated_origin_degree H x z₀ regular₀)
  · intro z regular P root
    let Q := P.comp (Polynomial.X + Polynomial.C x)
    have shiftedRoot :
        ((translateX x H).map (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval Q = 0 := by
      have transported := translateX_specialization x z P H
      change _ = (specializePoly z P H).comp (Polynomial.X + Polynomial.C x) at transported
      rw [root, Polynomial.zero_comp] at transported
      exact transported
    have initial : Q.eval 0 = P.eval x := by
      simp only [Q, Polynomial.eval_comp, Polynomial.eval_add,
        Polynomial.eval_X, Polynomial.eval_C, zero_add]
    have originRoot := response_supplies_origin_root (translateX x H) z Q shiftedRoot
    rw [initial] at originRoot
    obtain ⟨G, member, factorRoot⟩ := coverage z (P.eval x)
      (translated_origin_leading_coefficient_ne_zero H x z regular) originRoot
    exact ⟨G, member, factorRoot,
      translated_origin_derivative_at_root_ne_zero H positive x z (P.eval x)
        regular originRoot⟩

end
end HegemonCrypto.SmallWood.Mca38ActualOriginAssignment
