import HegemonCrypto.SmallWoodV8Smz9AdaptiveFiniteAccounting
import HegemonCrypto.SmallWoodPiopEvaluation
import HegemonCrypto.SmallWoodV8Smz9DisjointCoset

/-!
# Polynomial-root probability on the actual ideal SMZ9 admissible opening set

The six openings here inhabit `FullAdmissibleOpeningTuple`, including the correction-numerator
and PCS-unstack exclusions.  An all-roots event injects into ordered selections of distinct
polynomial roots.  Its cardinality is therefore at most `(degree)_6`; the already proved lower
bound on the admissible sample space gives denominator `(p - 64)_6 - 414 * p^5`.

The final specialization uses the current SMZ9 degree-552 nonlinear consistency discrepancy,
not the historical degree-544/five-opening profile.  Nonzeroness is derived from a failed batch
on the packing domain, and its degree bound is derived from the quotient/mask/batch bounds.
This is a finite uniform-sampling theorem, not an identification of Rust Fiat--Shamir output
with that law, a commitment/DECS extraction theorem, or a QROM or production-authority claim.
-/

namespace HegemonCrypto.SmallWood.V8Smz9AdmissibleRootProbability

open Polynomial
open V8Smz9AdaptiveFiniteAccounting
open V8Smz9AdaptiveFiniteAccounting.Historical

noncomputable section

set_option maxRecDepth 100000

/-- Admissible six-tuples on which one fixed polynomial vanishes at every coordinate. -/
abbrev AdmissibleRootTuple (polynomial : Goldilocks[X]) :=
  { accepted : FullAdmissibleOpeningTuple //
      ∀ coordinate, polynomial.eval (baseOpeningPoints accepted.1 coordinate) = 0 }

noncomputable instance (polynomial : Goldilocks[X]) :
    Fintype (AdmissibleRootTuple polynomial) := Fintype.ofFinite _

/-- Forgetting admissibility cannot identify two ordered root tuples. -/
def admissibleRootTupleEmbedding (polynomial : Goldilocks[X]) :
    AdmissibleRootTuple polynomial ↪
      (OpeningIndex ↪ { point // point ∈ FiniteFieldSampling.rootSet polynomial }) where
  toFun accepted :=
    { toFun := fun coordinate =>
        ⟨baseOpeningPoints accepted.1.1 coordinate,
          (FiniteFieldSampling.mem_root_set_iff polynomial _).mpr (accepted.2 coordinate)⟩
      inj' := by
        intro left right same
        apply baseOpeningPoints_injective accepted.1.1
        exact congrArg
          (fun point : { point // point ∈ FiniteFieldSampling.rootSet polynomial } => point.val)
          same }
  inj' := by
    intro left right same
    apply Subtype.ext
    apply Subtype.ext
    apply DFunLike.ext _ _
    intro coordinate
    apply Subtype.ext
    exact congrArg (fun tuple => (tuple coordinate).val) same

/-- Count the event by distinct roots; neither uniformity nor a probability bound is assumed. -/
theorem admissible_root_tuple_card_le
    {polynomial : Goldilocks[X]} (nonzero : polynomial ≠ 0) :
    Fintype.card (AdmissibleRootTuple polynomial) ≤
      fallingProduct polynomial.natDegree piopOpenings := by
  calc
    Fintype.card (AdmissibleRootTuple polynomial) ≤
        Fintype.card
          (OpeningIndex ↪ { point // point ∈ FiniteFieldSampling.rootSet polynomial }) :=
      Fintype.card_le_of_embedding (admissibleRootTupleEmbedding polynomial)
    _ = (FiniteFieldSampling.rootSet polynomial).card.descFactorial piopOpenings := by
      rw [Fintype.card_embedding_eq]
      simp [OpeningIndex]
    _ ≤ polynomial.natDegree.descFactorial piopOpenings :=
      Nat.descFactorial_le _ (FiniteFieldSampling.root_set_card_le_nat_degree nonzero)
    _ = fallingProduct polynomial.natDegree piopOpenings := by
      exact (UniformSubsetSampling.falling_product_eq_desc_factorial _ _).symm

theorem full_admissible_opening_tuple_card_positive :
    0 < Fintype.card FullAdmissibleOpeningTuple :=
  correction_aware_opening_denominator_is_positive.trans_le
    full_admissible_opening_tuple_card_lower_bound

/-- Exact rational probability under uniform sampling of the fully admissible tuples. -/
def uniformAdmissibleRootProbability (polynomial : Goldilocks[X]) : Rat :=
  Fintype.card (AdmissibleRootTuple polynomial) / Fintype.card FullAdmissibleOpeningTuple

/-- An integer certificate for the corrected-denominator root probability bound. -/
theorem admissible_root_probability_cross_multiply_le
    {polynomial : Goldilocks[X]} (nonzero : polynomial ≠ 0) :
    Fintype.card (AdmissibleRootTuple polynomial) * correctionAwareOpeningTupleLowerBound ≤
      fallingProduct polynomial.natDegree piopOpenings *
        Fintype.card FullAdmissibleOpeningTuple := by
  exact (Nat.mul_le_mul_right _ (admissible_root_tuple_card_le nonzero)).trans
    (Nat.mul_le_mul_left _ full_admissible_opening_tuple_card_lower_bound)

/-- Root event bound on the actual ideal admissible set, not on an unconditioned cube. -/
theorem uniform_admissible_root_probability_le
    {polynomial : Goldilocks[X]} (nonzero : polynomial ≠ 0) :
    uniformAdmissibleRootProbability polynomial ≤
      (fallingProduct polynomial.natDegree piopOpenings : Rat) /
        correctionAwareOpeningTupleLowerBound := by
  unfold uniformAdmissibleRootProbability
  apply (div_le_div_iff₀
    (by exact_mod_cast full_admissible_opening_tuple_card_positive)
    (by exact_mod_cast correction_aware_opening_denominator_is_positive)).mpr
  exact_mod_cast admissible_root_probability_cross_multiply_le nonzero

/-- The corrected ledger's third term is now a derived bound for every degree-552 discrepancy. -/
theorem uniform_admissible_root_probability_le_corrected_epsilon3
    {polynomial : Goldilocks[X]} (nonzero : polynomial ≠ 0)
    (degreeBound : polynomial.natDegree ≤ V8Smz9QromAccounting.piopConsistencyDiscrepancyDegree) :
    uniformAdmissibleRootProbability polynomial ≤
      (correctedEpsilon3.numerator : Rat) / correctedEpsilon3.denominator := by
  apply (uniform_admissible_root_probability_le nonzero).trans
  apply div_le_div_of_nonneg_right _ (by positivity)
  change (fallingProduct polynomial.natDegree piopOpenings : Rat) ≤
    fallingProduct V8Smz9QromAccounting.piopConsistencyDiscrepancyDegree piopOpenings
  exact_mod_cast (show fallingProduct polynomial.natDegree piopOpenings ≤
      fallingProduct V8Smz9QromAccounting.piopConsistencyDiscrepancyDegree piopOpenings by
    change Hegemon.Transaction.SmallWoodNoGrindingSoundness.fallingProduct _ _ ≤
      Hegemon.Transaction.SmallWoodNoGrindingSoundness.fallingProduct _ _
    simp only [UniformSubsetSampling.falling_product_eq_desc_factorial]
    exact Nat.descFactorial_le _ degreeBound)

/-- Exact current SMZ9 nonlinear discrepancy on the 64 fixed packing nodes. -/
def smz9ConsistencyDiscrepancy
    (batched claimedQuotient maskedPolynomial : Goldilocks[X]) : Goldilocks[X] :=
  PiopEvaluation.consistencyDiscrepancy (Finset.univ : Finset (Fin packingFactor))
    packingPoint batched claimedQuotient maskedPolynomial

theorem smz9_consistency_discrepancy_degree_le
    (batched claimedQuotient maskedPolynomial : Goldilocks[X])
    (claimedBound : claimedQuotient.natDegree ≤ V8Smz9QromAccounting.constraintPolynomialDegree)
    (maskBound : maskedPolynomial.natDegree ≤ V8Smz9QromAccounting.constraintPolynomialDegree)
    (batchedBound : batched.natDegree ≤ V8Smz9QromAccounting.batchedConstraintPolynomialDegree) :
    (smz9ConsistencyDiscrepancy batched claimedQuotient maskedPolynomial).natDegree ≤
      V8Smz9QromAccounting.piopConsistencyDiscrepancyDegree := by
  apply PiopEvaluation.consistency_discrepancy_natDegree_le
    (Finset.univ : Finset (Fin packingFactor)) packingPoint
    batched claimedQuotient maskedPolynomial packingFactor
    V8Smz9QromAccounting.constraintPolynomialDegree
  · simp
  · exact claimedBound
  · exact maskBound
  · exact batchedBound
  · decide

/-- A failed current-profile batch implies the corrected epsilon3 bound, with nonzeroness and
the degree-552 discrepancy bound proved here rather than supplied as security premises. -/
theorem smz9_false_batch_admissible_root_probability_le
    (batched claimedQuotient maskedPolynomial : Goldilocks[X])
    (lane : Fin packingFactor)
    (batchFailure : batched.eval (packingPoint lane) ≠ 0)
    (claimedBound : claimedQuotient.natDegree ≤ V8Smz9QromAccounting.constraintPolynomialDegree)
    (maskBound : maskedPolynomial.natDegree ≤ V8Smz9QromAccounting.constraintPolynomialDegree)
    (batchedBound : batched.natDegree ≤ V8Smz9QromAccounting.batchedConstraintPolynomialDegree) :
    uniformAdmissibleRootProbability
        (smz9ConsistencyDiscrepancy batched claimedQuotient maskedPolynomial) ≤
      (correctedEpsilon3.numerator : Rat) / correctedEpsilon3.denominator := by
  apply uniform_admissible_root_probability_le_corrected_epsilon3
  · exact PiopEvaluation.consistency_discrepancy_ne_zero_of_batch_failure
      (Finset.univ : Finset (Fin packingFactor)) packingPoint
      batched claimedQuotient maskedPolynomial lane (Finset.mem_univ lane) batchFailure
  · exact smz9_consistency_discrepancy_degree_le batched claimedQuotient maskedPolynomial
      claimedBound maskBound batchedBound

/-! ## Exact current DECS domain and twenty-element challenge -/

/-- Indices at which a fixed polynomial vanishes on the source-aligned SMZ9 disjoint coset. -/
def decsRootIndices (polynomial : Goldilocks[X]) : Finset (Fin decsDomainSize) :=
  Finset.univ.filter fun index =>
    polynomial.eval (V8Smz9DisjointCoset.evaluationPoint index) = 0

theorem decs_root_indices_card_le
    {polynomial : Goldilocks[X]} (nonzero : polynomial ≠ 0) :
    (decsRootIndices polynomial).card ≤ polynomial.natDegree := by
  let embedding :
      { index // index ∈ decsRootIndices polynomial } ↪
        { point // point ∈ FiniteFieldSampling.rootSet polynomial } :=
    { toFun := fun index =>
        ⟨V8Smz9DisjointCoset.evaluationPoint index.val,
          (FiniteFieldSampling.mem_root_set_iff polynomial _).mpr
            ((Finset.mem_filter.mp index.property).2)⟩
      inj' := by
        intro left right same
        apply Subtype.ext
        apply V8Smz9DisjointCoset.evaluation_point_injective
        exact congrArg
          (fun point : { point // point ∈ FiniteFieldSampling.rootSet polynomial } => point.val)
          same }
  have count : (decsRootIndices polynomial).card ≤
      (FiniteFieldSampling.rootSet polynomial).card := by
    simpa only [Fintype.card_coe] using Fintype.card_le_of_embedding embedding
  exact count.trans (FiniteFieldSampling.root_set_card_le_nat_degree nonzero)

/-- The all-roots event on the existing exact SMZ9 twenty-element DECS challenge type. -/
abbrev DecsRootChallenge (polynomial : Goldilocks[X]) :=
  { challenge : V8Smz9LogicalOracle.DecsOpeningChallenge //
      ∀ index ∈ challenge.val,
        polynomial.eval (V8Smz9DisjointCoset.evaluationPoint index) = 0 }

noncomputable instance (polynomial : Goldilocks[X]) :
    Fintype (DecsRootChallenge polynomial) := Fintype.ofFinite _

def decsRootChallengeEquivPowerset (polynomial : Goldilocks[X]) :
    DecsRootChallenge polynomial ≃
      { sample // sample ∈ (decsRootIndices polynomial).powersetCard decsOpenings } where
  toFun challenge := ⟨challenge.val.val, Finset.mem_powersetCard.mpr
    ⟨fun index membership => Finset.mem_filter.mpr
      ⟨Finset.mem_univ _, challenge.property index membership⟩, challenge.val.property⟩⟩
  invFun sample :=
    ⟨⟨sample.val, (Finset.mem_powersetCard.mp sample.property).2⟩,
      fun index membership =>
        (Finset.mem_filter.mp ((Finset.mem_powersetCard.mp sample.property).1 membership)).2⟩
  left_inv _ := by apply Subtype.ext; apply Subtype.ext; rfl
  right_inv _ := by apply Subtype.ext; rfl

theorem decs_root_challenge_card (polynomial : Goldilocks[X]) :
    Fintype.card (DecsRootChallenge polynomial) =
      Nat.choose (decsRootIndices polynomial).card decsOpenings := by
  rw [Fintype.card_congr (decsRootChallengeEquivPowerset polynomial)]
  simp only [Fintype.card_coe, Finset.card_powersetCard]

/-- Exact probability for uniform sampling of the already-defined DECS challenge type. -/
def uniformDecsRootProbability (polynomial : Goldilocks[X]) : Rat :=
  Fintype.card (DecsRootChallenge polynomial) /
    Fintype.card V8Smz9LogicalOracle.DecsOpeningChallenge

/-- Current degree-387/twenty-opening epsilon4 is a root-event bound on the exact disjoint coset.
No distributional claim about executable challenge derivation is included. -/
theorem uniform_decs_root_probability_le_corrected_epsilon4
    {polynomial : Goldilocks[X]} (nonzero : polynomial ≠ 0)
    (degreeBound : polynomial.natDegree ≤ V8Smz9QromAccounting.decsPolynomialDegree) :
    uniformDecsRootProbability polynomial ≤
      (correctedEpsilon4.numerator : Rat) / correctedEpsilon4.denominator := by
  unfold uniformDecsRootProbability
  rw [decs_root_challenge_card, V8Smz9LogicalOracle.decs_opening_challenge_card]
  change (Nat.choose (decsRootIndices polynomial).card decsOpenings : Rat) /
      Nat.choose decsDomainSize decsOpenings ≤
    (Hegemon.Transaction.SmallWoodNoGrindingSoundness.fallingProduct
      V8Smz9QromAccounting.decsPolynomialDegree decsOpenings : Rat) /
      Hegemon.Transaction.SmallWoodNoGrindingSoundness.fallingProduct decsDomainSize decsOpenings
  simp only [UniformSubsetSampling.falling_product_eq_desc_factorial]
  rw [UniformSubsetSampling.desc_factorial_ratio_eq_choose_ratio (by decide)]
  apply div_le_div_of_nonneg_right _ (Nat.cast_nonneg _)
  exact_mod_cast Nat.choose_le_choose decsOpenings
    ((decs_root_indices_card_le nonzero).trans degreeBound)

end

end HegemonCrypto.SmallWood.V8Smz9AdmissibleRootProbability
