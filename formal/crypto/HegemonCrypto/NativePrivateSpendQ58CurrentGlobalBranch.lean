/- Draft private-spend degree-13172 finite recovery instantiation.
Current COMPFF01 degree successor. Kernel check pending; no QROM endpoint asserted. -/
import HegemonCrypto.NativePrivateSpendQ58CurrentGlobalDescent
import HegemonCrypto.NativePrivateSpendQ58CurrentGlobalPosition
import Mca38IncidenceColumnCount
import Mca38AffineBadLabelCount

/-!
One-factor label counting for the actual localized Newton branch.

The branch decision is made once over the generic fraction-field root.  If it
is affine, the anti-fit condition charges every label to a position.  If it is
not affine, at most 13172 positions have an identical generic incidence, and the
actual per-position resultant bound controls every remaining column.  There is
no generic Newton-residual case in this split.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalBranch

open HegemonCrypto.SmallWood.Mca38Published
open HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalNewton
open HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalNumerator
open HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalPosition
open HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalDescent
open HegemonCrypto.SmallWood.Mca38IncidenceColumnCount
open HegemonCrypto.SmallWood.Mca38AffineBadLabelCount
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 0
set_option maxHeartbeats 0

variable {K I : Type*} [Field K] [DecidableEq I]

/-- The genuine finite data selected for each retained label.  All fields are
source-response facts; no obstruction count or generic residual premise is
stored in the record. -/
structure ActualSelectedResponses
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K))
    (labels : Finset K) (positions : Finset I)
    (point U V : I → K) where
  rootValue : K → K
  responsePolynomial : K → Polynomial K
  support : K → Finset I
  factorRoot : ∀ z ∈ labels,
    H.eval₂ (Polynomial.evalRingHom z) (rootValue z) = 0
  denominatorSimple : ∀ z ∈ labels,
    (coefficientOrigin F).derivative.eval₂
      (Polynomial.evalRingHom z) (rootValue z) ≠ 0
  responseDegree : ∀ z ∈ labels, (responsePolynomial z).natDegree ≤ 13172
  sourceRoot : ∀ z ∈ labels,
    (F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval
      (responsePolynomial z) = 0
  initialValue : ∀ z ∈ labels,
    (responsePolynomial z).eval 0 = rootValue z
  supportSubset : ∀ z ∈ labels, support z ⊆ positions
  supportLarge : ∀ z ∈ labels, 360448 ≤ (support z).card
  supportAgreement : ∀ z ∈ labels, ∀ a ∈ support z,
    (responsePolynomial z).eval (point a) = U a + z * V a
  supportBad : ∀ z ∈ labels, ∀ q : Polynomial K,
    q.natDegree ≤ 13172 → ¬ (∀ a ∈ support z, q.eval (point a) = V a)

/-- A fixed property of the generic branch.  It is independent of labels and
of the finite response selected at any label. -/
def actualBranchIsAffine
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K))
    [Fact (Irreducible (H.map (fractionMap (K := K))))]
    (denominator : AdjoinRoot.mk (H.map (fractionMap (K := K)))
      ((coefficientOrigin F).derivative.map (fractionMap (K := K))) ≠ 0) : Prop :=
  ∃ u v : Polynomial K, u.natDegree ≤ 13172 ∧ v.natDegree ≤ 13172 ∧
    genericNewtonResponse F H denominator =
      u.map (genericBaseMap H) + Polynomial.C (genericLabel H) *
        v.map (genericBaseMap H)

/-- The actual one-factor dichotomy, with the generic branch predicate kept in
the result so subsequent global partitions cannot accidentally choose a branch
separately for each label. -/
theorem actual_branch_label_count
    (F : Polynomial (Polynomial (Polynomial K)))
    (H : Polynomial (Polynomial K)) (primitive : H.IsPrimitive)
    [Fact (Irreducible (H.map (fractionMap (K := K))))]
    (denominator : AdjoinRoot.mk (H.map (fractionMap (K := K)))
      ((coefficientOrigin F).derivative.map (fractionMap (K := K))) ≠ 0)
    (m Z DH : Nat) (positive : 0 < m) (sourceDegree : F.natDegree ≤ m)
    (sourceHeight : ∀ j i, ((F.coeff j).coeff i).natDegree ≤ Z)
    (factorHeight : ∀ j, (H.coeff j).natDegree ≤ DH)
    (divides : H ∣ coefficientOrigin F)
    (labels : Finset K) (positions : Finset I) (point U V : I → K)
    (pointInjective : Set.InjOn point (positions : Set I))
    (selected : ActualSelectedResponses F H labels positions point U V) :
    (actualBranchIsAffine F H denominator ∧ labels.card ≤ positions.card) ∨
    (¬ actualBranchIsAffine F H denominator ∧
      labels.card * (360448 - 13172) ≤
        positions.card *
          (H.natDegree * (26343 * Z + 1) + (26343 * m) * DH)) := by
  classical
  by_cases affineBranch : actualBranchIsAffine F H denominator
  · apply Or.inl
    refine ⟨affineBranch, ?_⟩
    obtain ⟨u, v, uDegree, vDegree, affine⟩ := affineBranch
    apply card_labels_le_positions 13172 positions point U V u v uDegree vDegree labels
    intro z member
    refine ⟨selected.support z, selected.supportSubset z member, ?_,
      selected.supportBad z member⟩
    intro a inSupport
    have finiteAffine := actual_response_affine_of_generic_affine
      F H primitive denominator divides z (selected.rootValue z)
      (selected.factorRoot z member) (selected.denominatorSimple z member)
      (selected.responsePolynomial z) u v (selected.responseDegree z member)
      (selected.sourceRoot z member) (selected.initialValue z member) affine
    have agreement := selected.supportAgreement z member a inSupport
    rw [finiteAffine, Polynomial.eval_add, Polynomial.eval_mul,
      Polynomial.eval_C] at agreement
    exact agreement
  · apply Or.inr
    refine ⟨affineBranch, ?_⟩
    let identical : Finset I := positions.filter (fun a =>
      actualGenericMap F H denominator
        (actualIncidenceResidue F H (point a) (U a) (V a)) = 0)
    have fewIdentical : identical.card ≤ 13172 := by
      obtain ⟨u, v, uDegree, vDegree, genericAffine, _uniform⟩ | few :=
        all_actual_responses_affine_or_few_identical_positions
          F H primitive denominator divides point U V positions pointInjective
      · exact False.elim (affineBranch ⟨u, v, uDegree, vDegree, genericAffine⟩)
      · exact few
    have columnUpper : ∀ a ∈ positions \ identical,
        (labels.filter (fun z => a ∈ selected.support z)).card ≤
          H.natDegree * (26343 * Z + 1) + (26343 * m) * DH := by
      intro a outside
      have nonidentical : actualGenericMap F H denominator
          (actualIncidenceResidue F H (point a) (U a) (V a)) ≠ 0 := by
        intro zero
        exact (Finset.mem_sdiff.mp outside).2
          (Finset.mem_filter.mpr ⟨(Finset.mem_sdiff.mp outside).1, zero⟩)
      apply actual_position_label_count F H (fractionMap (K := K))
        (IsFractionRing.injective (Polynomial K) (FractionRing (Polynomial K)))
        denominator m Z DH positive sourceDegree sourceHeight factorHeight divides
        (point a) (U a) (V a) nonidentical
        (labels.filter (fun z => a ∈ selected.support z))
      intro z retained
      have member := (Finset.mem_filter.mp retained).1
      have inSupport := (Finset.mem_filter.mp retained).2
      exact ⟨selected.rootValue z, selected.factorRoot z member,
        selected.denominatorSimple z member, selected.responsePolynomial z,
        selected.responseDegree z member, selected.sourceRoot z member,
        selected.initialValue z member,
        selected.supportAgreement z member a inSupport⟩
    exact label_position_uniform_column_bound labels positions identical selected.support
      360448 13172 (H.natDegree * (26343 * Z + 1) + (26343 * m) * DH)
      selected.supportSubset selected.supportLarge fewIdentical columnUpper

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGlobalBranch
