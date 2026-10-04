import Mca38ActualPositionIncidenceCount
import Mca38AlgebraicAffineDescentR2
import Mathlib.RingTheory.Polynomial.GaussLemma

/-!
The actual localized Newton response, viewed at a primitive origin factor,
admits the algebraic affine-incidence dichotomy.  The affine alternative is
then transported back through the *injective* generic localization map and
specialized to the finite response.  Thus the returned affine polynomial is
the actual accepted response, rather than merely an unrelated polynomial over
the fraction-field root extension.
-/
namespace HegemonCrypto.SmallWood.Mca38GenericIncidenceDescent

open HegemonCrypto.SmallWood.Mca38Published
open HegemonCrypto.SmallWood.Mca38ActualPositionIncidenceCount
open HegemonCrypto.SmallWood.Mca38ActualNonaffineBranchCount
open scoped Classical

noncomputable section
set_option autoImplicit false

variable {K I : Type*} [Field K]

def fractionMap : Polynomial K →+* FractionRing (Polynomial K) :=
  algebraMap _ _

abbrev GenericRootField (H : Polynomial (Polynomial K)) :=
  AdjoinRoot (H.map (fractionMap (K := K)))

def genericBaseMap (H : Polynomial (Polynomial K)) :
    K →+* GenericRootField H :=
  (AdjoinRoot.of _).comp ((fractionMap (K := K)).comp Polynomial.C)

def genericLabel (H : Polynomial (Polynomial K)) : GenericRootField H :=
  AdjoinRoot.of _ (fractionMap (K := K) Polynomial.X)

def localizedScalarMap
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K)) : K →+* NewtonFactorLocalization F H :=
  (actualRootSourceMap F H).comp
    ((Polynomial.C : Polynomial K →+* Polynomial (Polynomial K)).comp Polynomial.C)

def localizedLabel
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K)) : NewtonFactorLocalization F H :=
  actualRootSourceMap F H (Polynomial.C Polynomial.X)

def actualGenericMap
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K))
    [Fact (Irreducible (H.map (fractionMap (K := K))))]
    (denominator : AdjoinRoot.mk (H.map (fractionMap (K := K)))
      ((coefficientOrigin F).derivative.map (fractionMap (K := K))) ≠ 0) :
    NewtonFactorLocalization F H →+* GenericRootField H :=
  finiteFactorGenericMap H (coefficientOrigin F).derivative
    (fractionMap (K := K)) denominator

def genericNewtonResponse
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K))
    [Fact (Irreducible (H.map (fractionMap (K := K))))]
    (denominator : AdjoinRoot.mk (H.map (fractionMap (K := K)))
      ((coefficientOrigin F).derivative.map (fractionMap (K := K))) ≠ 0) :
    Polynomial (GenericRootField H) :=
  (finiteNewtonResponse405 (actualLocalizedNewtonPolynomial F H)
    (actualLocalizedNewtonState F H)).map (actualGenericMap F H denominator)

theorem actualGenericMap_actualRootSource
    (F : Polynomial (Polynomial (Polynomial K)))
    (H p : Polynomial (Polynomial K))
    [Fact (Irreducible (H.map (fractionMap (K := K))))]
    (denominator : AdjoinRoot.mk (H.map (fractionMap (K := K)))
      ((coefficientOrigin F).derivative.map (fractionMap (K := K))) ≠ 0) :
    actualGenericMap F H denominator (actualRootSourceMap F H p) =
      AdjoinRoot.mk (H.map (fractionMap (K := K)))
        (p.map (fractionMap (K := K))) := by
  exact finiteFactorGenericMap_numerator H (coefficientOrigin F).derivative p
    (fractionMap (K := K)) denominator

theorem actualGenericMap_localizedScalar
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K))
    [Fact (Irreducible (H.map (fractionMap (K := K))))]
    (denominator : AdjoinRoot.mk (H.map (fractionMap (K := K)))
      ((coefficientOrigin F).derivative.map (fractionMap (K := K))) ≠ 0)
    (a : K) :
    actualGenericMap F H denominator (localizedScalarMap F H a) =
      genericBaseMap H a := by
  simp only [localizedScalarMap, RingHom.comp_apply,
    actualGenericMap_actualRootSource, Polynomial.map_C,
    genericBaseMap, AdjoinRoot.mk_C]

theorem actualGenericMap_localizedLabel
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K))
    [Fact (Irreducible (H.map (fractionMap (K := K))))]
    (denominator : AdjoinRoot.mk (H.map (fractionMap (K := K)))
      ((coefficientOrigin F).derivative.map (fractionMap (K := K))) ≠ 0) :
    actualGenericMap F H denominator (localizedLabel F H) = genericLabel H := by
  simp only [localizedLabel, actualGenericMap_actualRootSource, Polynomial.map_C,
    AdjoinRoot.mk_C, genericLabel]

theorem actual_incidence_generic_image
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K))
    [Fact (Irreducible (H.map (fractionMap (K := K))))]
    (denominator : AdjoinRoot.mk (H.map (fractionMap (K := K)))
      ((coefficientOrigin F).derivative.map (fractionMap (K := K))) ≠ 0)
    (x u v : K) :
    actualGenericMap F H denominator (actualIncidenceResidue F H x u v) =
      (genericNewtonResponse F H denominator).eval (genericBaseMap H x) -
        (genericBaseMap H u + genericLabel H * genericBaseMap H v) := by
  have line : actualRootSourceMap F H (Polynomial.C (affineLine u v)) =
      localizedScalarMap F H u + localizedLabel F H * localizedScalarMap F H v := by
    simp only [localizedScalarMap, localizedLabel, RingHom.comp_apply, affineLine,
      map_add, map_mul]
  unfold actualIncidenceResidue genericNewtonResponse
  simp only [actualRootSourceMap_C]
  have line' : localizedCoefficientMap F H (affineLine u v) =
      localizedScalarMap F H u + localizedLabel F H * localizedScalarMap F H v := by
    simpa only [actualRootSourceMap_C] using line
  rw [map_sub, ← Polynomial.eval_map_apply, line', map_add, map_mul]
  simp only [actualGenericMap_localizedScalar, actualGenericMap_localizedLabel]
  have point : actualGenericMap F H denominator
      (localizedCoefficientMap F H (Polynomial.C x)) = genericBaseMap H x := by
    simpa only [localizedScalarMap, RingHom.comp_apply, actualRootSourceMap_C] using
      actualGenericMap_localizedScalar F H denominator x
  rw [point]

/-- Gauss's lemma makes scalar extension of a primitive quotient injective.
This is the exact algebraic input needed to reflect the generic affine
identity; no blanket descent statement is assumed. -/
theorem genericQuotientMap_injective_of_primitive
    (H : Polynomial (Polynomial K)) (primitive : H.IsPrimitive) :
    Function.Injective
      (AdjoinRoot.map (fractionMap (K := K)) H
        (H.map (fractionMap (K := K))) (dvd_refl _)) := by
  intro a b equality
  obtain ⟨p, rfl⟩ := AdjoinRoot.mk_surjective a
  obtain ⟨q, rfl⟩ := AdjoinRoot.mk_surjective b
  rw [quotientBaseMap_mk, quotientBaseMap_mk] at equality
  apply AdjoinRoot.mk_eq_mk.mpr
  apply primitive.dvd_of_fraction_map_dvd_fraction_map
    (K := FractionRing (Polynomial K))
  simpa only [fractionMap, Polynomial.map_sub] using (AdjoinRoot.mk_eq_mk.mp equality)

/-- The finite-factor generic map is injective when the factor is primitive.
The proof uses the localization universal property plus the preceding Gauss
lemma argument; it does not posit torsion-freeness or injectivity as a premise.
-/
theorem actualGenericMap_injective_of_primitive
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K)) (primitive : H.IsPrimitive)
    [Fact (Irreducible (H.map (fractionMap (K := K))))]
    (denominator : AdjoinRoot.mk (H.map (fractionMap (K := K)))
      ((coefficientOrigin F).derivative.map (fractionMap (K := K))) ≠ 0) :
    Function.Injective (actualGenericMap F H denominator) := by
  let q := AdjoinRoot.map (fractionMap (K := K)) H
    (H.map (fractionMap (K := K))) (dvd_refl _)
  have qInjective : Function.Injective q :=
    genericQuotientMap_injective_of_primitive H primitive
  have unit : IsUnit (q (AdjoinRoot.mk H (coefficientOrigin F).derivative)) := by
    dsimp only [q]
    rw [quotientBaseMap_mk]
    exact isUnit_iff_ne_zero.mpr denominator
  change Function.Injective
    (IsLocalization.Away.lift (AdjoinRoot.mk H (coefficientOrigin F).derivative) unit)
  unfold IsLocalization.Away.lift
  rw [IsLocalization.lift_injective_iff]
  intro a b
  constructor
  · intro equality
    have mapped := congrArg
      (IsLocalization.Away.lift
        (AdjoinRoot.mk H (coefficientOrigin F).derivative) unit) equality
    simpa only [IsLocalization.Away.lift_eq] using mapped
  · intro equality
    exact congrArg (algebraMap (AdjoinRoot H) (NewtonFactorLocalization F H))
      (qInjective equality)

/-- Reflect a generic affine identity to the actual localized Newton response.
This is the key noncircular transport step. -/
theorem localized_response_affine_of_generic_affine
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K)) (primitive : H.IsPrimitive)
    [Fact (Irreducible (H.map (fractionMap (K := K))))]
    (denominator : AdjoinRoot.mk (H.map (fractionMap (K := K)))
      ((coefficientOrigin F).derivative.map (fractionMap (K := K))) ≠ 0)
    (u v : Polynomial K)
    (affine : genericNewtonResponse F H denominator =
      u.map (genericBaseMap H) + Polynomial.C (genericLabel H) *
        v.map (genericBaseMap H)) :
    finiteNewtonResponse405 (actualLocalizedNewtonPolynomial F H)
        (actualLocalizedNewtonState F H) =
      u.map (localizedScalarMap F H) + Polynomial.C (localizedLabel F H) *
        v.map (localizedScalarMap F H) := by
  apply Polynomial.map_injective _
    (actualGenericMap_injective_of_primitive F H primitive denominator)
  have genericScalar :
      (actualGenericMap F H denominator).comp (localizedScalarMap F H) =
        genericBaseMap H := by
    ext a
    exact actualGenericMap_localizedScalar F H denominator a
  simpa only [genericNewtonResponse, Polynomial.map_add, Polynomial.map_mul,
    Polynomial.map_C, Polynomial.map_map,
    actualGenericMap_localizedLabel, genericScalar] using affine

/-- Specializing the reflected identity gives the actual response polynomial,
not merely its values at the sampled positions. -/
theorem actual_response_affine_of_generic_affine
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K)) (primitive : H.IsPrimitive)
    [Fact (Irreducible (H.map (fractionMap (K := K))))]
    (denominator : AdjoinRoot.mk (H.map (fractionMap (K := K)))
      ((coefficientOrigin F).derivative.map (fractionMap (K := K))) ≠ 0)
    (divides : H ∣ coefficientOrigin F) (z t : K)
    (root : H.eval₂ (Polynomial.evalRingHom z) t = 0)
    (simple : (coefficientOrigin F).derivative.eval₂
      (Polynomial.evalRingHom z) t ≠ 0)
    (P u v : Polynomial K) (degree : P.natDegree ≤ 405)
    (response : (F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval P = 0)
    (initial : P.eval 0 = t)
    (affine : genericNewtonResponse F H denominator =
      u.map (genericBaseMap H) + Polynomial.C (genericLabel H) *
        v.map (genericBaseMap H)) :
    P = u + Polynomial.C z * v := by
  let σ := finiteFactorSpecialization H (coefficientOrigin F).derivative
    z t root simple
  have localized := localized_response_affine_of_generic_affine
    F H primitive denominator u v affine
  have tracking := actual_source_response_tracks_localized_newton F H divides
    z t root simple P degree response initial
  rw [tracking, localized, Polynomial.map_add, Polynomial.map_mul,
    Polynomial.map_C]
  have scalar : σ.comp (localizedScalarMap F H) = RingHom.id K := by
    ext a
    simp only [σ, localizedScalarMap, RingHom.comp_apply, actualRootSourceMap_C,
      finiteFactorSpecialization_localizedCoefficient, Polynomial.eval_C,
      RingHom.id_apply]
  have label : σ (localizedLabel F H) = z := by
    simp only [σ, localizedLabel, actualRootSourceMap_C,
      finiteFactorSpecialization_localizedCoefficient, Polynomial.eval_X]
  have mapScalar (q : Polynomial K) :
      (Polynomial.map σ (Polynomial.map (localizedScalarMap F H) q)) = q := by
    ext n
    simp only [Polynomial.coeff_map]
    simpa only [RingHom.comp_apply, RingHom.id_apply] using
      DFunLike.congr_fun scalar (q.coeff n)
  rw [mapScalar u, mapScalar v, label]

/-- The specialization-independent form of the incidence dichotomy.  In the
left branch the same pair `u,v` describes the generic Newton polynomial before
any challenge label is chosen. -/
theorem generic_response_affine_or_few_identical_positions
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K))
    [Fact (Irreducible (H.map (fractionMap (K := K))))]
    (denominator : AdjoinRoot.mk (H.map (fractionMap (K := K)))
      ((coefficientOrigin F).derivative.map (fractionMap (K := K))) ≠ 0)
    (divides : H ∣ coefficientOrigin F)
    (point U V : I → K) (positions : Finset I)
    (pointInjective : Set.InjOn point (positions : Set I)) :
    (∃ u v : Polynomial K, u.natDegree ≤ 405 ∧ v.natDegree ≤ 405 ∧
      genericNewtonResponse F H denominator =
        u.map (genericBaseMap H) + Polynomial.C (genericLabel H) *
          v.map (genericBaseMap H)) ∨
    (positions.filter (fun a =>
      actualGenericMap F H denominator
        (actualIncidenceResidue F H (point a) (U a) (V a)) = 0)).card ≤ 405 := by
  letI : Nontrivial (NewtonFactorLocalization F H) :=
    (actualGenericMap F H denominator).domain_nontrivial
  have responseDegree : (genericNewtonResponse F H denominator).natDegree ≤ 405 :=
    Polynomial.natDegree_map_le.trans
      (actualRootSource_response_properties F H divides).1
  obtain ⟨u, v, uDegree, vDegree, affine⟩ | few :=
    algebraic_branch_affine_or_few_identical_incidences
      (genericBaseMap H) (genericLabel H) (genericNewtonResponse F H denominator)
      405 responseDegree point U V positions pointInjective
  · exact Or.inl ⟨u, v, uDegree, vDegree, affine⟩
  · apply Or.inr
    calc
      (positions.filter (fun a =>
        actualGenericMap F H denominator
          (actualIncidenceResidue F H (point a) (U a) (V a)) = 0)).card =
          (positions.filter (fun a =>
            (genericNewtonResponse F H denominator).eval (genericBaseMap H (point a)) =
              genericBaseMap H (U a) + genericLabel H * genericBaseMap H (V a))).card := by
            congr 1
            ext a
            simp only [Finset.mem_filter]
            rw [actual_incidence_generic_image F H denominator (point a) (U a) (V a),
              sub_eq_zero]
      _ ≤ 405 := few

/-- Uniform production endpoint: the generic affine branch gives one pair
`u,v` which specializes to *every* finite accepted response attached to this
factor.  Otherwise the identical-position set has size at most 405. -/
theorem all_actual_responses_affine_or_few_identical_positions
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K)) (primitive : H.IsPrimitive)
    [Fact (Irreducible (H.map (fractionMap (K := K))))]
    (denominator : AdjoinRoot.mk (H.map (fractionMap (K := K)))
      ((coefficientOrigin F).derivative.map (fractionMap (K := K))) ≠ 0)
    (divides : H ∣ coefficientOrigin F)
    (point U V : I → K) (positions : Finset I)
    (pointInjective : Set.InjOn point (positions : Set I)) :
    (∃ u v : Polynomial K, u.natDegree ≤ 405 ∧ v.natDegree ≤ 405 ∧
      genericNewtonResponse F H denominator =
        u.map (genericBaseMap H) + Polynomial.C (genericLabel H) *
          v.map (genericBaseMap H) ∧
      ∀ z t : K, ∀ P : Polynomial K,
        H.eval₂ (Polynomial.evalRingHom z) t = 0 →
        (coefficientOrigin F).derivative.eval₂ (Polynomial.evalRingHom z) t ≠ 0 →
        P.natDegree ≤ 405 →
        (F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval P = 0 →
        P.eval 0 = t → P = u + Polynomial.C z * v) ∨
    (positions.filter (fun a =>
      actualGenericMap F H denominator
        (actualIncidenceResidue F H (point a) (U a) (V a)) = 0)).card ≤ 405 := by
  obtain ⟨u, v, uDegree, vDegree, affine⟩ | few :=
    generic_response_affine_or_few_identical_positions F H denominator divides
      point U V positions pointInjective
  · apply Or.inl
    refine ⟨u, v, uDegree, vDegree, affine, ?_⟩
    intro z t P root simple degree response initial
    exact actual_response_affine_of_generic_affine F H primitive denominator divides
      z t root simple P u v degree response initial affine
  · exact Or.inr few

/-- The production dichotomy.  Either the concrete specialized response is an
affine pair of degree at most 405, or at most 405 positions have an identical
generic source-line incidence. -/
theorem actual_response_affine_or_few_identical_positions
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K)) (primitive : H.IsPrimitive)
    [Fact (Irreducible (H.map (fractionMap (K := K))))]
    (denominator : AdjoinRoot.mk (H.map (fractionMap (K := K)))
      ((coefficientOrigin F).derivative.map (fractionMap (K := K))) ≠ 0)
    (divides : H ∣ coefficientOrigin F) (z t : K)
    (root : H.eval₂ (Polynomial.evalRingHom z) t = 0)
    (simple : (coefficientOrigin F).derivative.eval₂
      (Polynomial.evalRingHom z) t ≠ 0)
    (P : Polynomial K) (degree : P.natDegree ≤ 405)
    (response : (F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval P = 0)
    (initial : P.eval 0 = t)
    (point U V : I → K) (positions : Finset I)
    (pointInjective : Set.InjOn point (positions : Set I)) :
    (∃ u v : Polynomial K, u.natDegree ≤ 405 ∧ v.natDegree ≤ 405 ∧
      P = u + Polynomial.C z * v) ∨
    (positions.filter (fun a =>
      actualGenericMap F H denominator
        (actualIncidenceResidue F H (point a) (U a) (V a)) = 0)).card ≤ 405 := by
  obtain ⟨u, v, uDegree, vDegree, _, uniform⟩ | few :=
    all_actual_responses_affine_or_few_identical_positions F H primitive denominator
      divides point U V positions pointInjective
  · exact Or.inl ⟨u, v, uDegree, vDegree,
      uniform z t P root simple degree response initial⟩
  · exact Or.inr few

end
end HegemonCrypto.SmallWood.Mca38GenericIncidenceDescent
