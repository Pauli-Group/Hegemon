import Mca38ActualBranchLabelCount
import Mca38ActualOriginAssignment
import Mca38NestedRegularPartition
import Mca38WeightedBranchUnions
import Mca38BivariateHeightInterface
import Mca38ActualDerivativeDenominatorR2

/-!
Construct the finite outer/inner branch family used by the short global
incidence route.

Only outer factors which receive an actual regular selected response are kept.
Such a response constructs that outer factor's primitive origin family.  The
resulting dependent finite branch type covers every label outside the already
counted regular-start exception, and retains the exact inner and outer degree
ledgers needed by `weighted_incidence_budget`.  No residual-root partition or
global count is assumed here.
-/
namespace HegemonCrypto.SmallWood.Mca38GlobalIncidenceAssembly

open HegemonCrypto.SmallWood.Mca38Published
open HegemonCrypto.SmallWood.Mca38RoundByRound
open HegemonCrypto.SmallWood.Mca38RoundByRoundInterpolation
open HegemonCrypto.SmallWood.Mca38NestedFactorCoverage
open HegemonCrypto.SmallWood.Mca38NestedFactorSeparability
open HegemonCrypto.SmallWood.Mca38NestedInterpolationHeights
open HegemonCrypto.SmallWood.Mca38NestedRegularPartition
open HegemonCrypto.SmallWood.Mca38NestedTranslation
open HegemonCrypto.SmallWood.Mca38TranslatedRegularOrigin
open HegemonCrypto.SmallWood.Mca38ActualOriginAssignment
open HegemonCrypto.SmallWood.Mca38GenericIncidenceDescent
open HegemonCrypto.SmallWood.Mca38ActualBranchLabelCount
open HegemonCrypto.SmallWood.Mca38WeightedBranchUnions
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false

variable {K : Type*} [Field K]

abbrev Outer (K : Type*) [Field K] := Polynomial (Polynomial (Polynomial K))
abbrev Inner (K : Type*) [Field K] := Polynomial (Polynomial K)

def nestedSource (c : CoefficientIndex → K) : Outer K := trivariateNested c

def retainedLabels (c : CoefficientIndex → K) (x : K) (labels : Finset K) : Finset K :=
  labels \ badStartLabels (nestedSource c) x labels

/-- Outer factors which genuinely receive at least one retained selected
response.  The witness includes the exact regularity used to construct the
origin family. -/
def activeOuterFactors (c : CoefficientIndex → K) (x : K)
    (labels : Finset K) (response : K → Polynomial K) : Finset (Outer K) :=
  (factors (nestedSource c)).toFinset.filter fun H =>
    0 < H.natDegree ∧ ∃ z ∈ retainedLabels c x labels,
      specializePoly z (response z) H = 0 ∧
      ((regularityObstruction H).eval (Polynomial.C x)).eval z ≠ 0

abbrev ActiveOuterIndex (c : CoefficientIndex → K) (x : K)
    (labels : Finset K) (response : K → Polynomial K) :=
  {H // H ∈ activeOuterFactors c x labels response}

theorem activeOuterPositive
    {c : CoefficientIndex → K} {x : K} {labels : Finset K}
    {response : K → Polynomial K}
    (i : ActiveOuterIndex c x labels response) : 0 < i.1.natDegree :=
  (Finset.mem_filter.mp i.2).2.1

def activeRegularLabel
    {c : CoefficientIndex → K} {x : K} {labels : Finset K}
    {response : K → Polynomial K}
    (i : ActiveOuterIndex c x labels response) : K :=
  Classical.choose (Finset.mem_filter.mp i.2).2.2

theorem activeRegularLabel_spec
    {c : CoefficientIndex → K} {x : K} {labels : Finset K}
    {response : K → Polynomial K}
    (i : ActiveOuterIndex c x labels response) :
    activeRegularLabel i ∈ retainedLabels c x labels ∧
      specializePoly (activeRegularLabel i) (response (activeRegularLabel i)) i.1 = 0 ∧
      ((regularityObstruction i.1).eval (Polynomial.C x)).eval
        (activeRegularLabel i) ≠ 0 := by
  exact Classical.choose_spec (Finset.mem_filter.mp i.2).2.2

/-- The primitive origin family is chosen from an actual retained response of
the active outer factor. -/
def originFamily
    {c : CoefficientIndex → K} {x : K} {labels : Finset K}
    {response : K → Polynomial K}
    (i : ActiveOuterIndex c x labels response) : Multiset (Inner K) :=
  Classical.choose (exists_actual_origin_assignment i.1 (activeOuterPositive i) x
    (activeRegularLabel i) (activeRegularLabel_spec i).2.2)

theorem originFamily_spec
    {c : CoefficientIndex → K} {x : K} {labels : Finset K}
    {response : K → Polynomial K}
    (i : ActiveOuterIndex c x labels response) :
    (∀ G ∈ originFamily i, Irreducible G ∧ G.IsPrimitive ∧
      Irreducible (G.map (fractionMap (K := K))) ∧ 0 < G.natDegree ∧
      G ∣ coefficientOrigin (translateX x i.1)) ∧
    ((originFamily i).map Polynomial.natDegree).sum = i.1.natDegree ∧
    ((originFamily i).map bivariateCoefficientHeight).sum ≤ (zView i.1).natDegree ∧
    ∀ z : K, ((regularityObstruction i.1).eval (Polynomial.C x)).eval z ≠ 0 →
      ∀ P : Polynomial K, specializePoly z P i.1 = 0 →
        ∃ G ∈ originFamily i,
          G.eval₂ (Polynomial.evalRingHom z) (P.eval x) = 0 ∧
          (coefficientOrigin (translateX x i.1)).derivative.eval₂
            (Polynomial.evalRingHom z) (P.eval x) ≠ 0 := by
  exact Classical.choose_spec (exists_actual_origin_assignment i.1
    (activeOuterPositive i) x (activeRegularLabel i) (activeRegularLabel_spec i).2.2)

abbrev InnerIndex
    {c : CoefficientIndex → K} {x : K} {labels : Finset K}
    {response : K → Polynomial K}
    (i : ActiveOuterIndex c x labels response) :=
  {G // G ∈ (originFamily i).toFinset}

abbrev BranchIndex (c : CoefficientIndex → K) (x : K)
    (labels : Finset K) (response : K → Polynomial K) :=
  Σ i : ActiveOuterIndex c x labels response, InnerIndex i

def branchOuter
    {c : CoefficientIndex → K} {x : K} {labels : Finset K}
    {response : K → Polynomial K}
    (b : BranchIndex c x labels response) : Outer K := b.1.1

def branchInner
    {c : CoefficientIndex → K} {x : K} {labels : Finset K}
    {response : K → Polynomial K}
    (b : BranchIndex c x labels response) : Inner K := b.2.1

theorem branchInner_mem_originFamily
    {c : CoefficientIndex → K} {x : K} {labels : Finset K}
    {response : K → Polynomial K}
    (b : BranchIndex c x labels response) : branchInner b ∈ originFamily b.1 := by
  exact Multiset.mem_toFinset.mp b.2.2

def branchLabels
    {c : CoefficientIndex → K} {x : K} {labels : Finset K}
    {response : K → Polynomial K}
    (b : BranchIndex c x labels response) : Finset K :=
  (retainedLabels c x labels).filter fun z =>
    specializePoly z (response z) (branchOuter b) = 0 ∧
    ((regularityObstruction (branchOuter b)).eval (Polynomial.C x)).eval z ≠ 0 ∧
    (branchInner b).eval₂ (Polynomial.evalRingHom z) ((response z).eval x) = 0 ∧
    (coefficientOrigin (translateX x (branchOuter b))).derivative.eval₂
      (Polynomial.evalRingHom z) ((response z).eval x) ≠ 0

/-- Every retained selected response is covered by the constructed finite
dependent branch family. -/
theorem retained_label_branch_coverage
    (c : CoefficientIndex → K) (hc : c ≠ 0)
    (small : 810 < ringChar (FractionRing (Polynomial (Polynomial K))))
    (candidates labels : Finset K) (large : 530841600 < candidates.card)
    (response : K → Polynomial K)
    (sourceRoot : ∀ z ∈ labels, specializePoly z (response z) (nestedSource c) = 0) :
    ∃ x ∈ candidates,
      (badStartLabels (nestedSource c) x labels).card ≤ 16210000 ∧
      ∀ z ∈ retainedLabels c x labels,
        ∃ b : BranchIndex c x labels response, z ∈ branchLabels b := by
  obtain ⟨x, inCandidates, badCount, partition⟩ :=
    rbr_regular_start_partition c hc small candidates labels large
  refine ⟨x, inCandidates, badCount, ?_⟩
  intro z retained
  have member : z ∈ labels := (Finset.mem_sdiff.mp retained).1
  have outside : z ∉ badStartLabels (nestedSource c) x labels :=
    (Finset.mem_sdiff.mp retained).2
  obtain ⟨H, factor, positive, outerRoot, regular⟩ :=
    partition z member outside (response z) (sourceRoot z member)
  have active : H ∈ activeOuterFactors c x labels response := by
    apply Finset.mem_filter.mpr
    exact ⟨Multiset.mem_toFinset.mpr factor, positive, z, retained, outerRoot, regular⟩
  let i : ActiveOuterIndex c x labels response := ⟨H, active⟩
  obtain ⟨G, inner, innerRoot, simple⟩ :=
    (originFamily_spec i).2.2.2 z regular (response z) outerRoot
  let j : InnerIndex i := ⟨G, Multiset.mem_toFinset.mpr inner⟩
  let b : BranchIndex c x labels response := ⟨i, j⟩
  refine ⟨b, Finset.mem_filter.mpr ⟨retained, ?_⟩⟩
  exact ⟨outerRoot, regular, innerRoot, simple⟩

/-- Removing duplicates when passing from a multiset factorization to its
finite index set can only decrease a natural-valued additive ledger. -/
theorem sum_toFinset_le_multiset_sum {A : Type*} [DecidableEq A]
    (s : Multiset A) (w : A → Nat) :
    ∑ a ∈ s.toFinset, w a ≤ (s.map w).sum := by
  induction s using Multiset.induction_on with
  | empty => simp
  | @cons a s ih =>
      by_cases member : a ∈ s
      · rw [Multiset.toFinset_cons,
          Finset.insert_eq_of_mem (Multiset.mem_toFinset.mpr member),
          Multiset.map_cons, Multiset.sum_cons]
        exact ih.trans (Nat.le_add_left _ _)
      · rw [Multiset.toFinset_cons,
          Finset.sum_insert (by simpa only [Multiset.mem_toFinset]),
          Multiset.map_cons, Multiset.sum_cons]
        exact Nat.add_le_add_left ih _

theorem active_outer_degree_ledgers
    (c : CoefficientIndex → K) (hc : c ≠ 0) (x : K)
    (labels : Finset K) (response : K → Polynomial K) :
    (∑ H ∈ activeOuterFactors c x labels response, H.natDegree) ≤ 810 ∧
    (∑ H ∈ activeOuterFactors c x labels response, (zView H).natDegree) ≤ 10000 := by
  have subset : activeOuterFactors c x labels response ⊆ (factors (nestedSource c)).toFinset :=
    Finset.filter_subset _ _
  have heights := actual_nested_interpolant_heights c
  have sourceNonzero := trivariateNested_ne_zero c hc
  constructor
  · calc
      _ ≤ ∑ H ∈ (factors (nestedSource c)).toFinset, H.natDegree :=
        Finset.sum_le_sum_of_subset_of_nonneg subset (fun _ _ _ => Nat.zero_le _)
      _ ≤ ((factors (nestedSource c)).map Polynomial.natDegree).sum :=
        sum_toFinset_le_multiset_sum _ _
      _ = (nestedSource c).natDegree := (degree_ledger (nestedSource c) sourceNonzero).1
      _ ≤ 810 := heights.1
  · calc
      _ ≤ ∑ H ∈ (factors (nestedSource c)).toFinset, (zView H).natDegree :=
        Finset.sum_le_sum_of_subset_of_nonneg subset (fun _ _ _ => Nat.zero_le _)
      _ ≤ ((factors (nestedSource c)).map (fun H => (zView H).natDegree)).sum :=
        sum_toFinset_le_multiset_sum _ _
      _ = (zView (nestedSource c)).natDegree :=
        (degree_ledger (nestedSource c) sourceNonzero).2.2
      _ ≤ 10000 := heights.2.2

/-- Exact per-outer inner ledgers and all algebraic premises needed by the
one-factor branch count. -/
theorem active_origin_ledgers_and_branch_data
    {c : CoefficientIndex → K} {x : K} {labels : Finset K}
    {response : K → Polynomial K}
    (i : ActiveOuterIndex c x labels response) :
    ((originFamily i).map Polynomial.natDegree).sum = i.1.natDegree ∧
    ((originFamily i).map bivariateCoefficientHeight).sum ≤ (zView i.1).natDegree ∧
    ∀ G ∈ originFamily i,
      G.IsPrimitive ∧ Irreducible (G.map (fractionMap (K := K))) ∧
      G ∣ coefficientOrigin (translateX x i.1) ∧
      (translateX x i.1).natDegree = i.1.natDegree ∧
      (∀ j k, (((translateX x i.1).coeff j).coeff k).natDegree ≤
        (zView i.1).natDegree) ∧
      (∀ j, (G.coeff j).natDegree ≤ bivariateCoefficientHeight G) := by
  have spec := originFamily_spec i
  refine ⟨spec.2.1, spec.2.2.1, ?_⟩
  intro G member
  have properties := spec.1 G member
  exact ⟨properties.2.1, properties.2.2.1, properties.2.2.2.2,
    translateX_Y_degree x i.1,
    fun j k => translateX_Z_coefficient_height x i.1 j k,
    coefficient_natDegree_le_bivariateHeight G⟩

/-- The generic Newton denominator for every constructed branch follows from
the actual regular witness used to build its outer origin family. -/
theorem branch_generic_denominator_nonzero
    {c : CoefficientIndex → K} {x : K} {labels : Finset K}
    {response : K → Polynomial K}
    (b : BranchIndex c x labels response) :
    AdjoinRoot.mk ((branchInner b).map (fractionMap (K := K)))
      ((coefficientOrigin (translateX x (branchOuter b))).derivative.map
        (fractionMap (K := K))) ≠ 0 := by
  let i := b.1
  have member := branchInner_mem_originFamily b
  have properties := (originFamily_spec i).1 (branchInner b) member
  apply actual_derivative_generic_nonzero
    (coefficientOrigin (translateX x (branchOuter b))) (branchInner b)
    (fractionMap (K := K)) properties.2.2.1 properties.2.2.2.2
  simpa only [translatedOrigin, fractionMap, branchOuter] using
    translated_origin_generic_separable (branchOuter b)
      (activeOuterPositive i) x (activeRegularLabel i) (activeRegularLabel_spec i).2.2

def shiftedPoint (x : K) {I : Type*} (point : I → K) : I → K :=
  fun a => point a - x

theorem shiftedPoint_injOn (x : K) {I : Type*} (point : I → K)
    (positions : Finset I) (injective : Set.InjOn point (positions : Set I)) :
    Set.InjOn (shiftedPoint x point) (positions : Set I) := by
  intro a ha b hb equality
  apply injective ha hb
  change point a - x = point b - x at equality
  have restored := congrArg (fun y : K => y + x) equality
  simpa only [sub_add_cancel] using restored

def translatedResponse (x : K) (response : K → Polynomial K) (z : K) : Polynomial K :=
  (response z).comp (Polynomial.X + Polynomial.C x)

/-- Every constructed branch inherits the genuine selected response/support
record required by the one-factor count, after translating evaluation points
by the common start.  Anti-fit is invariant under this translation. -/
def branch_selected_responses
    {c : CoefficientIndex → K} {x : K} {labels : Finset K}
    {response : K → Polynomial K}
    (b : BranchIndex c x labels response)
    {I : Type*} [DecidableEq I] (positions : Finset I) (point U V : I → K)
    (responseDegree : ∀ z ∈ labels, (response z).natDegree ≤ 405)
    (support : K → Finset I)
    (supportSubset : ∀ z ∈ labels, support z ⊆ positions)
    (supportLarge : ∀ z ∈ labels, 65536 ≤ (support z).card)
    (agreement : ∀ z ∈ labels, ∀ a ∈ support z,
      (response z).eval (point a) = U a + z * V a)
    (supportBad : ∀ z ∈ labels, ∀ q : Polynomial K,
      q.natDegree ≤ 405 → ¬ (∀ a ∈ support z, q.eval (point a) = V a)) :
    ActualSelectedResponses (translateX x (branchOuter b)) (branchInner b)
      (branchLabels b) positions (shiftedPoint x point) U V := by
  classical
  refine
    { rootValue := fun z => (response z).eval x
      responsePolynomial := translatedResponse x response
      support := support
      factorRoot := ?_
      denominatorSimple := ?_
      responseDegree := ?_
      sourceRoot := ?_
      initialValue := ?_
      supportSubset := ?_
      supportLarge := ?_
      supportAgreement := ?_
      supportBad := ?_ }
  · intro z member
    exact (Finset.mem_filter.mp member).2.2.2.1
  · intro z member
    exact (Finset.mem_filter.mp member).2.2.2.2
  · intro z member
    have original : z ∈ labels :=
      (Finset.mem_sdiff.mp (Finset.mem_filter.mp member).1).1
    exact translated_response_degree x (response z) (responseDegree z original)
  · intro z member
    have outerRoot := (Finset.mem_filter.mp member).2.1
    have transported := translateX_specialization x z (response z) (branchOuter b)
    change _ = (specializePoly z (response z) (branchOuter b)).comp
      (Polynomial.X + Polynomial.C x) at transported
    rw [outerRoot, Polynomial.zero_comp] at transported
    exact transported
  · intro z member
    simp only [translatedResponse, Polynomial.eval_comp, Polynomial.eval_add,
      Polynomial.eval_X, Polynomial.eval_C, zero_add]
  · intro z member
    have original : z ∈ labels :=
      (Finset.mem_sdiff.mp (Finset.mem_filter.mp member).1).1
    exact supportSubset z original
  · intro z member
    have original : z ∈ labels :=
      (Finset.mem_sdiff.mp (Finset.mem_filter.mp member).1).1
    exact supportLarge z original
  · intro z member a inSupport
    have original : z ∈ labels :=
      (Finset.mem_sdiff.mp (Finset.mem_filter.mp member).1).1
    have agreed := agreement z original a inSupport
    simpa only [translatedResponse, shiftedPoint, Polynomial.eval_comp,
      Polynomial.eval_add, Polynomial.eval_X, Polynomial.eval_C, sub_add_cancel]
      using agreed
  · intro z member q degree fit
    have original : z ∈ labels :=
      (Finset.mem_sdiff.mp (Finset.mem_filter.mp member).1).1
    let unshifted := q.comp (Polynomial.X + Polynomial.C (-x))
    apply supportBad z original unshifted
      (translated_response_degree (-x) q degree)
    intro a inSupport
    have fitted := fit a inSupport
    simpa only [unshifted, shiftedPoint, Polynomial.eval_comp,
      Polynomial.eval_add, Polynomial.eval_X, Polynomial.eval_C,
      sub_eq_add_neg] using fitted

def constructedBranchIsAffine
    {c : CoefficientIndex → K} {x : K} {labels : Finset K}
    {response : K → Polynomial K}
    (b : BranchIndex c x labels response) : Prop := by
  let properties := (originFamily_spec b.1).1 (branchInner b)
    (branchInner_mem_originFamily b)
  letI : Fact (Irreducible ((branchInner b).map (fractionMap (K := K)))) :=
    ⟨properties.2.2.1⟩
  exact actualBranchIsAffine (translateX x (branchOuter b)) (branchInner b)
    (branch_generic_denominator_nonzero b)

/-- Direct one-factor counting theorem for every member of the constructed
global branch family.  Its right-hand weight is exactly the summand consumed
by the outer/inner additive ledgers. -/
theorem constructed_branch_label_count
    {c : CoefficientIndex → K} {x : K} {labels : Finset K}
    {response : K → Polynomial K}
    (b : BranchIndex c x labels response)
    {I : Type*} [DecidableEq I] (positions : Finset I) (point U V : I → K)
    (pointInjective : Set.InjOn point (positions : Set I))
    (responseDegree : ∀ z ∈ labels, (response z).natDegree ≤ 405)
    (support : K → Finset I)
    (supportSubset : ∀ z ∈ labels, support z ⊆ positions)
    (supportLarge : ∀ z ∈ labels, 65536 ≤ (support z).card)
    (agreement : ∀ z ∈ labels, ∀ a ∈ support z,
      (response z).eval (point a) = U a + z * V a)
    (supportBad : ∀ z ∈ labels, ∀ q : Polynomial K,
      q.natDegree ≤ 405 → ¬ (∀ a ∈ support z, q.eval (point a) = V a)) :
    (constructedBranchIsAffine b ∧
      (branchLabels b).card ≤ positions.card) ∨
    (¬ constructedBranchIsAffine b ∧
      (branchLabels b).card * (65536 - 405) ≤ positions.card *
        ((branchInner b).natDegree * (809 * (zView (branchOuter b)).natDegree + 1) +
          (809 * (branchOuter b).natDegree) * bivariateCoefficientHeight (branchInner b))) := by
  let i := b.1
  have member := branchInner_mem_originFamily b
  have properties := (originFamily_spec i).1 (branchInner b) member
  letI : Fact (Irreducible ((branchInner b).map (fractionMap (K := K)))) :=
    ⟨properties.2.2.1⟩
  let denominator := branch_generic_denominator_nonzero b
  have count := actual_branch_label_count
    (translateX x (branchOuter b)) (branchInner b) properties.2.1 denominator
    (branchOuter b).natDegree (zView (branchOuter b)).natDegree
    (bivariateCoefficientHeight (branchInner b)) (activeOuterPositive i)
    (translateX_Y_degree x (branchOuter b)).le
    (fun j k => translateX_Z_coefficient_height x (branchOuter b) j k)
    (fun j => coefficient_natDegree_le_bivariateHeight (branchInner b) j)
    properties.2.2.2.2 (branchLabels b) positions (shiftedPoint x point) U V
    (shiftedPoint_injOn x point positions pointInjective)
    (branch_selected_responses b positions point U V responseDegree support
      supportSubset supportLarge agreement supportBad)
  simpa only [constructedBranchIsAffine] using count

def branchIncidenceWeight
    {c : CoefficientIndex → K} {x : K} {labels : Finset K}
    {response : K → Polynomial K}
    (b : BranchIndex c x labels response) : Nat :=
  (branchInner b).natDegree * (809 * (zView (branchOuter b)).natDegree + 1) +
    809 * (branchOuter b).natDegree * bivariateCoefficientHeight (branchInner b)

theorem branch_incidence_weight_sum_le
    (c : CoefficientIndex → K) (hc : c ≠ 0) (x : K)
    (labels : Finset K) (response : K → Polynomial K) :
    (∑ b : BranchIndex c x labels response, branchIncidenceWeight b) ≤
      1618 * 810 * 10000 + 810 := by
  have outerLedgers := active_outer_degree_ledgers c hc x labels response
  have outerY : (∑ i : ActiveOuterIndex c x labels response, i.1.natDegree) ≤ 810 := by
    have hsum :
        (∑ i : ActiveOuterIndex c x labels response, i.1.natDegree) =
          ∑ H ∈ activeOuterFactors c x labels response, H.natDegree := by
      exact (Finset.sum_subtype (activeOuterFactors c x labels response)
        (fun H => Iff.rfl) (fun H => H.natDegree)).symm
    exact hsum ▸ outerLedgers.1
  have outerZ :
      (∑ i : ActiveOuterIndex c x labels response, (zView i.1).natDegree) ≤ 10000 := by
    have hsum :
        (∑ i : ActiveOuterIndex c x labels response, (zView i.1).natDegree) =
          ∑ H ∈ activeOuterFactors c x labels response, (zView H).natDegree := by
      exact (Finset.sum_subtype (activeOuterFactors c x labels response)
        (fun H => Iff.rfl) (fun H => (zView H).natDegree)).symm
    exact hsum ▸ outerLedgers.2
  have fiber : ∀ i : ActiveOuterIndex c x labels response,
      (∑ j : InnerIndex i, branchIncidenceWeight (⟨i, j⟩)) ≤
        i.1.natDegree * (809 * (zView i.1).natDegree + 1) +
          809 * i.1.natDegree * (zView i.1).natDegree := by
    intro i
    have spec := originFamily_spec i
    have innerY : (∑ j : InnerIndex i, j.1.natDegree) ≤ i.1.natDegree := by
      calc
        _ = ∑ G ∈ (originFamily i).toFinset, G.natDegree := by
          exact (Finset.sum_subtype (originFamily i).toFinset
            (fun G => Iff.rfl) (fun G => G.natDegree)).symm
        _ ≤ ((originFamily i).map Polynomial.natDegree).sum :=
          sum_toFinset_le_multiset_sum _ _
        _ = i.1.natDegree := spec.2.1
    have innerZ :
        (∑ j : InnerIndex i, bivariateCoefficientHeight j.1) ≤
          (zView i.1).natDegree := by
      calc
        _ = ∑ G ∈ (originFamily i).toFinset, bivariateCoefficientHeight G := by
          exact (Finset.sum_subtype (originFamily i).toFinset
            (fun G => Iff.rfl) (fun G => bivariateCoefficientHeight G)).symm
        _ ≤ ((originFamily i).map bivariateCoefficientHeight).sum :=
          sum_toFinset_le_multiset_sum _ _
        _ ≤ (zView i.1).natDegree := spec.2.2.1
    simp only [branchIncidenceWeight, branchInner, branchOuter,
      Finset.sum_add_distrib, ← Finset.sum_mul, ← Finset.mul_sum]
    exact Nat.add_le_add
      (Nat.mul_le_mul_right (809 * (zView i.1).natDegree + 1) innerY)
      (Nat.mul_le_mul_left (809 * i.1.natDegree) innerZ)
  rw [Fintype.sum_sigma]
  calc
    _ ≤ ∑ i : ActiveOuterIndex c x labels response,
        (i.1.natDegree * (809 * (zView i.1).natDegree + 1) +
          809 * i.1.natDegree * (zView i.1).natDegree) :=
      Finset.sum_le_sum (fun i _ => fiber i)
    _ ≤ 1618 * 810 * 10000 + 810 := by
      exact weighted_incidence_budget
        (Finset.univ : Finset (ActiveOuterIndex c x labels response))
        (fun i => i.1.natDegree) (fun i => (zView i.1).natDegree)
        (fun i => i.1.natDegree) (fun i => (zView i.1).natDegree)
        810 10000 outerY outerZ (fun _ _ => le_rfl) (fun _ _ => le_rfl)

theorem branch_index_card_le
    (c : CoefficientIndex → K) (hc : c ≠ 0) (x : K)
    (labels : Finset K) (response : K → Polynomial K) :
    Fintype.card (BranchIndex c x labels response) ≤ 810 := by
  rw [Fintype.card_sigma]
  have fiber : ∀ i : ActiveOuterIndex c x labels response,
      Fintype.card (InnerIndex i) ≤ i.1.natDegree := by
    intro i
    calc
      Fintype.card (InnerIndex i) = ((originFamily i).toFinset).card := by simp
      _ = ∑ G ∈ (originFamily i).toFinset, 1 := by simp
      _ ≤ ∑ G ∈ (originFamily i).toFinset, G.natDegree := by
        apply Finset.sum_le_sum
        intro G member
        exact ((originFamily_spec i).1 G
          (Multiset.mem_toFinset.mp member)).2.2.2.1
      _ ≤ ((originFamily i).map Polynomial.natDegree).sum :=
        sum_toFinset_le_multiset_sum _ _
      _ = i.1.natDegree := (originFamily_spec i).2.1
  calc
    _ ≤ ∑ i : ActiveOuterIndex c x labels response, i.1.natDegree :=
      Finset.sum_le_sum (fun i _ => fiber i)
    _ ≤ 810 := by
      have hsum :
          (∑ i : ActiveOuterIndex c x labels response, i.1.natDegree) =
            ∑ H ∈ activeOuterFactors c x labels response, H.natDegree := by
        exact (Finset.sum_subtype (activeOuterFactors c x labels response)
          (fun H => Iff.rfl) (fun H => H.natDegree)).symm
      exact hsum ▸ (active_outer_degree_ledgers c hc x labels response).1

/-- Unconditional source-level endpoint for the short incidence route.  All
branch families and their assignment are constructed above; the only labels
outside them are the already counted regular-start exceptions. -/
theorem actual_global_incidence_label_count
    (c : CoefficientIndex → K) (hc : c ≠ 0)
    (small : 810 < ringChar (FractionRing (Polynomial (Polynomial K))))
    (candidates labels : Finset K) (large : 530841600 < candidates.card)
    (point U V : Fin 8388608 → K) (pointInjective : Function.Injective point)
    (response : K → Polynomial K)
    (responseDegree : ∀ z ∈ labels, (response z).natDegree ≤ 405)
    (sourceRoot : ∀ z ∈ labels,
      specializePoly z (response z) (nestedSource c) = 0)
    (support : K → Finset (Fin 8388608))
    (supportLarge : ∀ z ∈ labels, 65536 ≤ (support z).card)
    (agreement : ∀ z ∈ labels, ∀ a ∈ support z,
      (response z).eval (point a) = U a + z * V a)
    (supportBad : ∀ z ∈ labels, ∀ q : Polynomial K,
      q.natDegree ≤ 405 → ¬ (∀ a ∈ support z, q.eval (point a) = V a)) :
    labels.card ≤ 1694784843179 := by
  classical
  obtain ⟨x, _xMember, badCount, coverage⟩ :=
    retained_label_branch_coverage c hc small candidates labels large response sourceRoot
  let positions : Finset (Fin 8388608) := Finset.univ
  let affine : Finset (BranchIndex c x labels response) :=
    Finset.univ.filter constructedBranchIsAffine
  let nonaffine : Finset (BranchIndex c x labels response) :=
    Finset.univ.filter (fun b => ¬ constructedBranchIsAffine b)
  let affineLabels : Finset K := affine.biUnion branchLabels
  let nonaffineLabels : Finset K := nonaffine.biUnion branchLabels
  have retainedCovered : retainedLabels c x labels ⊆ affineLabels ∪ nonaffineLabels := by
    intro z retained
    obtain ⟨b, inBranch⟩ := coverage z retained
    by_cases isAffine : constructedBranchIsAffine b
    · apply Finset.mem_union_left
      exact Finset.mem_biUnion.mpr
        ⟨b, Finset.mem_filter.mpr ⟨Finset.mem_univ _, isAffine⟩, inBranch⟩
    · apply Finset.mem_union_right
      exact Finset.mem_biUnion.mpr
        ⟨b, Finset.mem_filter.mpr ⟨Finset.mem_univ _, isAffine⟩, inBranch⟩
  have allCovered : labels ⊆
      badStartLabels (nestedSource c) x labels ∪ (affineLabels ∪ nonaffineLabels) := by
    intro z member
    by_cases bad : z ∈ badStartLabels (nestedSource c) x labels
    · exact Finset.mem_union_left _ bad
    · exact Finset.mem_union_right _
        (retainedCovered (Finset.mem_sdiff.mpr ⟨member, bad⟩))
  have affineEach : ∀ b ∈ affine, (branchLabels b).card ≤ positions.card := by
    intro b member
    have count := constructed_branch_label_count b positions point U V
      pointInjective.injOn responseDegree support
      (fun _ _ => Finset.subset_univ _) supportLarge agreement supportBad
    obtain bounded | bounded := count
    · exact bounded.2
    · exact False.elim (bounded.1 (Finset.mem_filter.mp member).2)
  have affineCard : affineLabels.card ≤ 8388608 * 810 := by
    have branches : affine.card ≤ 810 := by
      exact (Finset.card_le_card (Finset.filter_subset _ _)).trans
        (by simpa only [Finset.card_univ] using
          branch_index_card_le c hc x labels response)
    calc
      affineLabels.card ≤ ∑ b ∈ affine, (branchLabels b).card :=
        card_biUnion_le_sum_card affine branchLabels
      _ ≤ ∑ _b ∈ affine, positions.card := Finset.sum_le_sum affineEach
      _ = affine.card * positions.card := by simp
      _ ≤ 810 * 8388608 := by
        apply Nat.mul_le_mul branches
        simp only [positions, Finset.card_univ, Fintype.card_fin, le_refl]
      _ = 8388608 * 810 := by omega
  have nonaffineProduct :
      nonaffineLabels.card * (65536 - 405) ≤
        8388608 * (1618 * 810 * 10000 + 810) := by
    have columns : ∀ b ∈ nonaffine,
        (branchLabels b).card * (65536 - 405) ≤
          positions.card * branchIncidenceWeight b := by
      intro b member
      have count := constructed_branch_label_count b positions point U V
        pointInjective.injOn responseDegree support
        (fun _ _ => Finset.subset_univ _) supportLarge agreement supportBad
      obtain bounded | bounded := count
      · exact False.elim ((Finset.mem_filter.mp member).2 bounded.1)
      · exact bounded.2
    have weight : (∑ b ∈ nonaffine, branchIncidenceWeight b) ≤
        1618 * 810 * 10000 + 810 := by
      exact (Finset.sum_le_sum_of_subset_of_nonneg (Finset.filter_subset _ _)
        (fun _ _ _ => Nat.zero_le _)).trans
          (by simpa using
            branch_incidence_weight_sum_le c hc x labels response)
    calc
      nonaffineLabels.card * (65536 - 405) ≤
          (∑ b ∈ nonaffine, (branchLabels b).card) * (65536 - 405) :=
        Nat.mul_le_mul_right _ (card_biUnion_le_sum_card nonaffine branchLabels)
      _ = ∑ b ∈ nonaffine, (branchLabels b).card * (65536 - 405) := by
        rw [Finset.sum_mul]
      _ ≤ ∑ b ∈ nonaffine, positions.card * branchIncidenceWeight b :=
        Finset.sum_le_sum columns
      _ = positions.card * (∑ b ∈ nonaffine, branchIncidenceWeight b) := by
        rw [Finset.mul_sum]
      _ ≤ 8388608 * (1618 * 810 * 10000 + 810) := by
        apply Nat.mul_le_mul
        · simp only [positions, Finset.card_univ, Fintype.card_fin, le_refl]
        · exact weight
  have nonaffineCard : nonaffineLabels.card ≤ 1687973860698 := by
    have divided : nonaffineLabels.card ≤
        (8388608 * (1618 * 810 * 10000 + 810)) / (65536 - 405) :=
      (Nat.le_div_iff_mul_le (by norm_num : 0 < 65536 - 405)).2 nonaffineProduct
    norm_num at divided
    exact divided
  calc
    labels.card ≤
        (badStartLabels (nestedSource c) x labels ∪
          (affineLabels ∪ nonaffineLabels)).card := Finset.card_le_card allCovered
    _ ≤ (badStartLabels (nestedSource c) x labels).card +
        (affineLabels ∪ nonaffineLabels).card := Finset.card_union_le _ _
    _ ≤ (badStartLabels (nestedSource c) x labels).card +
        (affineLabels.card + nonaffineLabels.card) :=
      Nat.add_le_add_left (Finset.card_union_le _ _) _
    _ ≤ 16210000 + ((8388608 * 810) + 1687973860698) :=
      Nat.add_le_add badCount (Nat.add_le_add affineCard nonaffineCard)
    _ ≤ 1694784843179 := by norm_num

theorem actual_global_incidence_label_count_le_original_budget
    (c : CoefficientIndex → K) (hc : c ≠ 0)
    (small : 810 < ringChar (FractionRing (Polynomial (Polynomial K))))
    (candidates labels : Finset K) (large : 530841600 < candidates.card)
    (point U V : Fin 8388608 → K) (pointInjective : Function.Injective point)
    (response : K → Polynomial K)
    (responseDegree : ∀ z ∈ labels, (response z).natDegree ≤ 405)
    (sourceRoot : ∀ z ∈ labels,
      specializePoly z (response z) (nestedSource c) = 0)
    (support : K → Finset (Fin 8388608))
    (supportLarge : ∀ z ∈ labels, 65536 ≤ (support z).card)
    (agreement : ∀ z ∈ labels, ∀ a ∈ support z,
      (response z).eval (point a) = U a + z * V a)
    (supportBad : ∀ z ∈ labels, ∀ q : Polynomial K,
      q.natDegree ≤ 405 → ¬ (∀ a ∈ support z, q.eval (point a) = V a)) :
    labels.card ≤ 12310499043179 := by
  exact (actual_global_incidence_label_count c hc small candidates labels large
    point U V pointInjective response responseDegree sourceRoot support supportLarge
    agreement supportBad).trans (by norm_num)

end
end HegemonCrypto.SmallWood.Mca38GlobalIncidenceAssembly
