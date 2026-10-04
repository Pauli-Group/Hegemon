import Mca38GlobalIncidenceAssembly
import Mca38UniversalMatrixEvent
import Mca38ExtensionCharacteristic

/-!
# Concrete 65,536-support bad-line count

This is the final adapter from the actual response-universal line predicate to
the checked round-by-round interpolant and the global incidence count.  The
response polynomial and its full agreement support may depend on the label;
both are selected only after membership in the finite bad-line set is known.
No count, factor partition, multiplicity, or response-selection hypothesis is
supplied to the endpoint.
-/
namespace HegemonCrypto.SmallWood.Mca38UniversalBadLineCount

open Polynomial
open HegemonCrypto.SmallWood.V8Smz9McaRecovery
open HegemonCrypto.SmallWood.Mca38Closure
open HegemonCrypto.SmallWood.Mca38VectorTransport
open HegemonCrypto.SmallWood.Mca38ConcreteExtension
open HegemonCrypto.SmallWood.Mca38ExtensionCharacteristic
open HegemonCrypto.SmallWood.Mca38RoundByRound
open HegemonCrypto.SmallWood.Mca38NestedFactorCoverage
open HegemonCrypto.SmallWood.Mca38GlobalIncidenceAssembly
open HegemonCrypto.SmallWood.Q38DecoderEvent
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024

-- Keep the concrete AdjoinRoot basis and its induced finite instance opaque
-- while elaborating the universal endpoint; their definitions are not part
-- of this endpoint's proof and unfolding them causes pathological recursion.
attribute [local irreducible]
  HegemonCrypto.SmallWood.Mca38ConcreteExtension.basis5
  HegemonCrypto.SmallWood.Mca38ConcreteExtension.extensionFintype

/-- Construct witnesses over an abstract field before specializing the
concrete quotient field and its finite enumeration. -/
theorem encoded_witnesses
    {F K Position : Type*} [Field F] [Field K] [Algebra F K]
    [Fintype F] [Fintype Position]
    (basis : Module.Basis (Fin 5) F K) (point : Position → F)
    (degree cutoff : Nat) (prior : Fin 5 → Position → F) (direction : Position → F) :
    ∀ z ∈ (Mca38Closure.badSupportLabels point degree cutoff prior direction).image
      (encode basis),
      ∃ P : Polynomial K, ∃ S : Finset Position,
        P.natDegree ≤ degree ∧ cutoff ≤ S.card ∧
        (∀ a ∈ S, P.eval (algebraMap F K (point a)) =
          encodeWord basis prior a + z * algebraMap F K (direction a)) ∧
        (∀ q : Polynomial K, q.natDegree ≤ degree →
          ¬ (∀ a ∈ S, q.eval (algebraMap F K (point a)) =
            algebraMap F K (direction a))) := by
  classical
  intro z member
  obtain ⟨S, large, coded, bad⟩ :=
    encoded_label_image_bad basis point degree cutoff prior direction z member
  obtain ⟨P, bounded, agrees⟩ := coded
  exact ⟨P, S, bounded, large, agrees, fun q qBound agreesDirection =>
    bad ⟨q, qBound, agreesDirection⟩⟩

theorem select_response_support
    {K Position : Type*} [Field K]
    (labels : Finset K) (point U V : Position → K) (degree cutoff : Nat)
    (witnesses : ∀ z ∈ labels,
      ∃ P : Polynomial K, ∃ S : Finset Position,
        P.natDegree ≤ degree ∧ cutoff ≤ S.card ∧
        (∀ a ∈ S, P.eval (point a) = U a + z * V a) ∧
        (∀ q : Polynomial K, q.natDegree ≤ degree →
          ¬ (∀ a ∈ S, q.eval (point a) = V a))) :
    ∃ response : K → Polynomial K, ∃ support : K → Finset Position,
      ∀ z ∈ labels,
        (response z).natDegree ≤ degree ∧ cutoff ≤ (support z).card ∧
        (∀ a ∈ support z, (response z).eval (point a) = U a + z * V a) ∧
        (∀ q : Polynomial K, q.natDegree ≤ degree →
          ¬ (∀ a ∈ support z, q.eval (point a) = V a)) := by
  classical
  let response : K → Polynomial K := fun z =>
    if member : z ∈ labels then Classical.choose (witnesses z member) else 0
  let support : K → Finset Position := fun z =>
    if member : z ∈ labels then
      Classical.choose (Classical.choose_spec (witnesses z member)) else ∅
  refine ⟨response, support, ?_⟩
  intro z member
  simp only [response, support, dif_pos member]
  exact Classical.choose_spec (Classical.choose_spec (witnesses z member))

theorem scalar_bad_labels_bound
    {K : Type*} [Field K]
    (small : 810 < ringChar (FractionRing (Polynomial (Polynomial K))))
    (candidates labels : Finset K) (candidatesLarge : 530841600 < candidates.card)
    (point U V : Position38 → K) (pointInjective : Function.Injective point)
    (witnesses : ∀ z ∈ labels,
      ∃ P : Polynomial K, ∃ S : Finset Position38,
        P.natDegree ≤ 405 ∧ 65536 ≤ S.card ∧
        (∀ a ∈ S, P.eval (point a) = U a + z * V a) ∧
        (∀ q : Polynomial K, q.natDegree ≤ 405 →
          ¬ (∀ a ∈ S, q.eval (point a) = V a))) :
    labels.card ≤ 12310499043179 := by
  classical
  obtain ⟨response, support, picked⟩ :=
    select_response_support labels point U V 405 65536 witnesses
  obtain ⟨c, Q, _Qeq, _Qne, hc, _sourceNe, _nestedNe, _solve,
      _weightedBounds, _coordinateBounds, _sourceIdentity,
      _polynomialIdentity, supportVanishing⟩ :=
    exists_rbr_polynomial_endpoint point U V pointInjective
  have sourceRoot : ∀ z ∈ labels,
      specializePoly z (response z) (nestedSource c) = 0 := by
    intro z member
    rw [nestedSource, specialize_trivariateNested]
    exact supportVanishing z (response z) (picked z member).1 (support z)
      (picked z member).2.1 (picked z member).2.2.1
  exact actual_global_incidence_label_count_le_original_budget
    c hc small candidates labels candidatesLarge point U V pointInjective response
    (fun z member => (picked z member).1) sourceRoot support
    (fun z member => (picked z member).2.1)
    (fun z member => (picked z member).2.2.1)
    (fun z member => (picked z member).2.2.2)

/-- The two retained formulations of an exceptional line are extensionally
equal: negating the universal `LineGood` property is exactly exhibiting one
bounded response whose full agreement support is large and bad. -/
theorem badLineLabels_eq_badSupportLabels
    {F Position Row : Type*} [Field F] [Fintype F]
    [Fintype Position] [Fintype Row]
    (point : Position → F) (degree cutoff : ℕ)
    (prior : Row → Position → F) (direction : Position → F) :
    HegemonCrypto.SmallWood.Mca38UniversalMatrixEvent.badLineLabels
        point degree cutoff prior direction =
      Mca38Closure.badSupportLabels point degree cutoff prior direction := by
  classical
  ext coefficient
  simp only [HegemonCrypto.SmallWood.Mca38UniversalMatrixEvent.badLineLabels,
    Mca38Closure.badSupportLabels, Finset.mem_filter, Finset.mem_univ, true_and]
  constructor
  · intro exceptional
    unfold LineGood at exceptional
    push Not at exceptional
    obtain ⟨response, bounded, large, bad⟩ := exceptional
    refine ⟨boundedResponseOfPolynomials response bounded, ?_, ?_⟩
    · simpa only [bounded_response_roundtrip] using large
    · simpa only [bounded_response_roundtrip] using bad
  · rintro ⟨response, large, bad⟩ good
    exact bad (good (responsePolynomials response)
      (bounded_response_degree response) large)

/-- The actual five-row response-universal exceptional-label set at support
65,536 satisfies the unchanged production budget. -/
theorem universal_badLineLabels_65536
    (prior : Fin 5 → Position38 → Goldilocks)
    (direction : Position38 → Goldilocks) :
    (HegemonCrypto.SmallWood.Mca38UniversalMatrixEvent.badLineLabels
      V8Smz9DisjointCoset.evaluationPoint 405 65536 prior direction).card ≤
        12310499043179 := by
  classical
  let labels : Finset Extension5 := encodedBadLabels 65536 prior direction
  let U : Position38 → Extension5 := encodeWord basis5 prior
  let V : Position38 → Extension5 := fun index =>
    algebraMap Goldilocks Extension5 (direction index)
  have witnesses : ∀ z ∈ labels,
      ∃ P : Polynomial Extension5, ∃ S : Finset Position38,
        P.natDegree ≤ 405 ∧ 65536 ≤ S.card ∧
        (∀ a ∈ S, P.eval (embeddedPoint a) = U a + z * V a) ∧
        (∀ q : Polynomial Extension5, q.natDegree ≤ 405 →
          ¬ (∀ a ∈ S, q.eval (embeddedPoint a) = V a)) :=
    encoded_witnesses basis5 V8Smz9DisjointCoset.evaluationPoint 405 65536 prior direction
  let Target := FractionRing (Polynomial (Polynomial Extension5))
  letI targetCharP : CharP Target 18446744069414584321 :=
    charP_of_injective_algebraMap
      (algebraMap Extension5 Target).injective 18446744069414584321
  have small : 810 < ringChar Target := by
    rw [ringChar.eq Target 18446744069414584321]
    norm_num
  have candidatesLarge :
      530841600 < (Finset.univ : Finset Extension5).card := by
    simp only [Finset.card_univ]
    rw [← Nat.card_eq_fintype_card, extension_card]
    norm_num [goldilocksModulus]
  have scalarCount : labels.card ≤ 12310499043179 :=
    scalar_bad_labels_bound small Finset.univ labels candidatesLarge
      embeddedPoint U V embeddedPoint_injective witnesses
  calc
    (HegemonCrypto.SmallWood.Mca38UniversalMatrixEvent.badLineLabels
      V8Smz9DisjointCoset.evaluationPoint 405 65536 prior direction).card =
        (Mca38Closure.badSupportLabels V8Smz9DisjointCoset.evaluationPoint
          405 65536 prior direction).card :=
      congrArg Finset.card (badLineLabels_eq_badSupportLabels
        V8Smz9DisjointCoset.evaluationPoint 405 65536 prior direction)
    _ = labels.card := by
      symm
      simpa only [labels] using encodedBadLabels_card 65536 prior direction
    _ ≤ 12310499043179 := scalarCount

end
end HegemonCrypto.SmallWood.Mca38UniversalBadLineCount
