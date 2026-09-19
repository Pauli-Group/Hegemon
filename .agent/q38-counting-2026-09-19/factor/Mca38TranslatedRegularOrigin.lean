import Mca38NestedRegularPartition
import Mca38NestedTranslation

/-!
Transport one actual positive-Y factor's regularity to the translated X-origin.

The regular-partition obstruction is evaluated first at the chosen X
coordinate and then at the live label Z.  Its two nonzero factors give the
translated origin its genuine leading coefficient and a resultant Bezout
identity after specialization.  Separability and the derivative-at-root fact
are therefore conclusions for this factor, not family-wide hypotheses.
-/
namespace HegemonCrypto.SmallWood.Mca38TranslatedRegularOrigin

open HegemonCrypto.SmallWood.Mca38Published
open HegemonCrypto.SmallWood.Mca38NestedFactorSeparability
open HegemonCrypto.SmallWood.Mca38NestedTranslation
open scoped Classical

noncomputable section
set_option autoImplicit false

variable {K : Type*} [Field K]

def translatedOrigin (x : K) (H : Tri (K := K)) :
    Polynomial (Polynomial K) :=
  coefficientOrigin (translateX x H)

theorem translated_origin_eq_map (x : K) (H : Tri (K := K)) :
    translatedOrigin x H = H.map (Polynomial.evalRingHom (Polynomial.C x)) := by
  exact translateX_origin x H

theorem translated_origin_specialization (x z : K) (H : Tri (K := K)) :
    (translatedOrigin x H).map (Polynomial.evalRingHom z) =
      H.map ((Polynomial.evalRingHom z).comp
        (Polynomial.evalRingHom (Polynomial.C x))) := by
  rw [translated_origin_eq_map, Polynomial.map_map]

theorem regularity_parts_at_translated_origin
    (H : Tri (K := K)) (x z : K)
    (regular : ((regularityObstruction H).eval (Polynomial.C x)).eval z ≠ 0) :
    ((H.leadingCoeff.eval (Polynomial.C x)).eval z ≠ 0) ∧
      (((H.resultant H.derivative).eval (Polynomial.C x)).eval z ≠ 0) := by
  simpa only [regularityObstruction, Polynomial.eval_mul, mul_ne_zero_iff] using regular

theorem translated_origin_degree
    (H : Tri (K := K)) (x z : K)
    (regular : ((regularityObstruction H).eval (Polynomial.C x)).eval z ≠ 0) :
    (translatedOrigin x H).natDegree = H.natDegree := by
  have parts := regularity_parts_at_translated_origin H x z regular
  have leadingAtX : H.leadingCoeff.eval (Polynomial.C x) ≠ 0 := by
    intro zero
    apply parts.1
    rw [zero, Polynomial.eval_zero]
  rw [translated_origin_eq_map]
  exact Polynomial.natDegree_map_of_leadingCoeff_ne_zero
    (Polynomial.evalRingHom (Polynomial.C x)) leadingAtX

theorem translated_origin_leading_coefficient_ne_zero
    (H : Tri (K := K)) (x z : K)
    (regular : ((regularityObstruction H).eval (Polynomial.C x)).eval z ≠ 0) :
    (translatedOrigin x H).leadingCoeff.eval z ≠ 0 := by
  have parts := regularity_parts_at_translated_origin H x z regular
  have leadingAtX : H.leadingCoeff.eval (Polynomial.C x) ≠ 0 := by
    intro zero
    apply parts.1
    rw [zero, Polynomial.eval_zero]
  rw [translated_origin_eq_map,
    Polynomial.leadingCoeff_map_of_leadingCoeff_ne_zero
      (Polynomial.evalRingHom (Polynomial.C x)) leadingAtX]
  exact parts.1

/-- The actual translated-origin specialization is separable.  The proof maps
the resultant Bezout identity through the concrete two-coordinate evaluation;
it does not assume separability for the factor family. -/
theorem translated_origin_specialized_separable
    (H : Tri (K := K)) (positive : 0 < H.natDegree) (x z : K)
    (regular : ((regularityObstruction H).eval (Polynomial.C x)).eval z ≠ 0) :
    ((translatedOrigin x H).map (Polynomial.evalRingHom z)).Separable := by
  let φx : Polynomial (Polynomial K) →+* Polynomial K :=
    Polynomial.evalRingHom (Polynomial.C x)
  let φz : Polynomial K →+* K := Polynomial.evalRingHom z
  let φ : Polynomial (Polynomial K) →+* K := φz.comp φx
  have parts := regularity_parts_at_translated_origin H x z regular
  have resultantNonzero : φ (H.resultant H.derivative) ≠ 0 := by
    change ((H.resultant H.derivative).eval (Polynomial.C x)).eval z ≠ 0
    exact parts.2
  obtain ⟨a, b, _, _, bezout⟩ := Polynomial.exists_mul_add_mul_eq_C_resultant
    H H.derivative (le_refl _) (le_refl _) (Or.inl (Nat.ne_of_gt positive))
  have mappedBezout :
      H.map φ * a.map φ + (H.map φ).derivative * b.map φ =
        Polynomial.C (φ (H.resultant H.derivative)) := by
    simpa only [Polynomial.map_add, Polynomial.map_mul, Polynomial.map_C,
      Polynomial.derivative_map] using congrArg (Polynomial.map φ) bezout
  rw [translated_origin_specialization]
  apply (Polynomial.separable_def _).mpr
  refine ⟨a.map φ * Polynomial.C (φ (H.resultant H.derivative))⁻¹,
    b.map φ * Polynomial.C (φ (H.resultant H.derivative))⁻¹, ?_⟩
  calc
    a.map φ * Polynomial.C (φ (H.resultant H.derivative))⁻¹ * H.map φ +
          b.map φ * Polynomial.C (φ (H.resultant H.derivative))⁻¹ *
            (H.map φ).derivative =
        (H.map φ * a.map φ + (H.map φ).derivative * b.map φ) *
          Polynomial.C (φ (H.resultant H.derivative))⁻¹ := by ring
    _ = Polynomial.C (φ (H.resultant H.derivative)) *
          Polynomial.C (φ (H.resultant H.derivative))⁻¹ := by rw [mappedBezout]
    _ = 1 := by
      rw [← Polynomial.C_mul, mul_inv_cancel₀ resultantNonzero, Polynomial.C_1]

/-- A single actual regular specialization also certifies separability of the
translated origin over the fraction field of `K[Z]`.  The proof transports the
same resultant Bezout identity used above; injectivity of the fraction map,
not a family-wide separability premise, keeps its constant nonzero. -/
theorem translated_origin_generic_separable
    (H : Tri (K := K)) (positive : 0 < H.natDegree) (x z : K)
    (regular : ((regularityObstruction H).eval (Polynomial.C x)).eval z ≠ 0) :
    ((translatedOrigin x H).map
      (algebraMap (Polynomial K) (FractionRing (Polynomial K)))).Separable := by
  let φx : Polynomial (Polynomial K) →+* Polynomial K :=
    Polynomial.evalRingHom (Polynomial.C x)
  let φq : Polynomial K →+* FractionRing (Polynomial K) := algebraMap _ _
  let φ : Polynomial (Polynomial K) →+* FractionRing (Polynomial K) :=
    φq.comp φx
  have parts := regularity_parts_at_translated_origin H x z regular
  have resultantAtX : φx (H.resultant H.derivative) ≠ 0 := by
    intro zero
    apply parts.2
    change Polynomial.eval z (φx (H.resultant H.derivative)) = 0
    rw [zero, Polynomial.eval_zero]
  have resultantNonzero : φ (H.resultant H.derivative) ≠ 0 := by
    intro zero
    apply resultantAtX
    apply IsFractionRing.injective (Polynomial K) (FractionRing (Polynomial K))
    simpa only [φ, φq, RingHom.comp_apply, map_zero] using zero
  obtain ⟨a, b, _, _, bezout⟩ := Polynomial.exists_mul_add_mul_eq_C_resultant
    H H.derivative (le_refl _) (le_refl _) (Or.inl (Nat.ne_of_gt positive))
  have mappedBezout :
      H.map φ * a.map φ + (H.map φ).derivative * b.map φ =
        Polynomial.C (φ (H.resultant H.derivative)) := by
    simpa only [Polynomial.map_add, Polynomial.map_mul, Polynomial.map_C,
      Polynomial.derivative_map] using congrArg (Polynomial.map φ) bezout
  rw [translated_origin_eq_map, Polynomial.map_map]
  change (H.map φ).Separable
  apply (Polynomial.separable_def _).mpr
  refine ⟨a.map φ * Polynomial.C (φ (H.resultant H.derivative))⁻¹,
    b.map φ * Polynomial.C (φ (H.resultant H.derivative))⁻¹, ?_⟩
  calc
    a.map φ * Polynomial.C (φ (H.resultant H.derivative))⁻¹ * H.map φ +
          b.map φ * Polynomial.C (φ (H.resultant H.derivative))⁻¹ *
            (H.map φ).derivative =
        (H.map φ * a.map φ + (H.map φ).derivative * b.map φ) *
          Polynomial.C (φ (H.resultant H.derivative))⁻¹ := by ring
    _ = Polynomial.C (φ (H.resultant H.derivative)) *
          Polynomial.C (φ (H.resultant H.derivative))⁻¹ := by rw [mappedBezout]
    _ = 1 := by
      rw [← Polynomial.C_mul, mul_inv_cancel₀ resultantNonzero, Polynomial.C_1]

theorem translated_origin_regularity
    (H : Tri (K := K)) (positive : 0 < H.natDegree) (x z : K)
    (regular : ((regularityObstruction H).eval (Polynomial.C x)).eval z ≠ 0) :
    0 < (translatedOrigin x H).natDegree ∧
      (translatedOrigin x H).leadingCoeff.eval z ≠ 0 ∧
      ((translatedOrigin x H).map (Polynomial.evalRingHom z)).Separable := by
  refine ⟨?_, translated_origin_leading_coefficient_ne_zero H x z regular,
    translated_origin_specialized_separable H positive x z regular⟩
  rw [translated_origin_degree H x z regular]
  exact positive

/-- Every specialized root of the translated origin is simple. -/
theorem translated_origin_derivative_at_root_ne_zero
    (H : Tri (K := K)) (positive : 0 < H.natDegree) (x z t : K)
    (regular : ((regularityObstruction H).eval (Polynomial.C x)).eval z ≠ 0)
    (root : (translatedOrigin x H).eval₂ (Polynomial.evalRingHom z) t = 0) :
    (translatedOrigin x H).derivative.eval₂ (Polynomial.evalRingHom z) t ≠ 0 := by
  have separable := translated_origin_specialized_separable H positive x z regular
  have specializedRoot :
      ((translatedOrigin x H).map (Polynomial.evalRingHom z)).eval t = 0 := by
    simpa only [Polynomial.eval_map] using root
  have simple := separable.eval₂_derivative_ne_zero (RingHom.id K)
    (by simpa using specializedRoot)
  simpa only [Polynomial.eval₂_id, Polynomial.derivative_map,
    Polynomial.eval_map] using simple

/-- Form used by origin-factor coverage: a root of any actual divisor of the
translated origin has a nonzero derivative denominator for the source. -/
theorem translated_origin_derivative_at_divisor_root_ne_zero
    (H : Tri (K := K)) (positive : 0 < H.natDegree) (x z t : K)
    (regular : ((regularityObstruction H).eval (Polynomial.C x)).eval z ≠ 0)
    (J : Polynomial (Polynomial K)) (divides : J ∣ translatedOrigin x H)
    (root : J.eval₂ (Polynomial.evalRingHom z) t = 0) :
    (translatedOrigin x H).derivative.eval₂ (Polynomial.evalRingHom z) t ≠ 0 := by
  have originRoot :
      (translatedOrigin x H).eval₂ (Polynomial.evalRingHom z) t = 0 := by
    obtain ⟨q, product⟩ := divides
    rw [product, Polynomial.eval₂_mul, root, zero_mul]
  exact translated_origin_derivative_at_root_ne_zero
    H positive x z t regular originRoot

end
end HegemonCrypto.SmallWood.Mca38TranslatedRegularOrigin
