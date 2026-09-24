import HegemonCrypto.SmallWoodInteractive
import HegemonCrypto.UniformSubsetSampling

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# SmallWood PIOP evaluation soundness

The production verifier reconstructs a claimed masked quotient `Q`, opens the committed nonlinear
mask `M`, and checks

`Q(e) = F(e) / Z(e) + M(e)`

at five distinct points outside the 64-point packing domain.  Here `F` is the batched nonlinear
constraint polynomial and `Z` is the packing-domain vanishing polynomial.  A false claim therefore
defines the nonzero polynomial

`D = Z * (Q - M) - F`.

This module proves that `D` is nonzero whenever the batch fails at a packing point, bounds its
degree by 544 for the active profile, and derives the exact without-replacement failure term over
the `|Goldilocks| - 64` valid opening domain.  This is deterministic finite-field algebra; the
Fiat--Shamir/QROM transfer is kept separate.
-/

namespace HegemonCrypto.SmallWood.PiopEvaluation

open Polynomial
open HegemonCrypto.FiniteFieldSampling
open HegemonCrypto.UniformSubsetSampling
open HegemonCrypto.SmallWood.Interactive
open Hegemon.Transaction.SmallWoodNoGrindingSoundness
open Hegemon.Transaction.SmallWoodTranscriptBinding

noncomputable section

variable {F Node : Type*}
variable [Field F]

/-- Field points occupied by the finite packing domain. -/
def packingPointSet
    [DecidableEq F]
    (nodes : Finset Node)
    (point : Node -> F) : Finset F :=
  nodes.image point

/-- Field points at which the quotient equation may be evaluated. -/
def outsidePackingDomain
    [Fintype F] [DecidableEq F]
    (nodes : Finset Node)
    (point : Node -> F) : Finset F :=
  Finset.univ \ packingPointSet nodes point

/-- Roots of one polynomial that are also valid quotient-opening points. -/
def rootsOutsidePacking
    [Fintype F] [DecidableEq F]
    (nodes : Finset Node)
    (point : Node -> F)
    (polynomial : F[X]) : Finset F :=
  rootSet polynomial ∩ outsidePackingDomain nodes point

/-- Cross-multiplied form of the production nonlinear quotient check. -/
def consistencyDiscrepancy
    (nodes : Finset Node)
    (point : Node -> F)
    (batched claimedQuotient maskedPolynomial : F[X]) : F[X] :=
  packingVanishing nodes point * (claimedQuotient - maskedPolynomial) - batched

/-- The packing vanishing polynomial evaluates to zero at every packing point. -/
theorem packing_vanishing_eval_at_node
    [DecidableEq Node]
    (nodes : Finset Node)
    (point : Node -> F)
    (node : Node)
    (nodeMembership : node ∈ nodes) :
    (packingVanishing nodes point).eval (point node) = 0 := by
  classical
  rw [packingVanishing, Polynomial.eval_prod]
  apply Finset.prod_eq_zero nodeMembership
  simp

/-- At a packing point, the consistency discrepancy is the negated batched constraint value. -/
theorem consistency_discrepancy_eval_at_node
    [DecidableEq Node]
    (nodes : Finset Node)
    (point : Node -> F)
    (batched claimedQuotient maskedPolynomial : F[X])
    (node : Node)
    (nodeMembership : node ∈ nodes) :
    (consistencyDiscrepancy nodes point batched claimedQuotient maskedPolynomial).eval
        (point node) =
      -batched.eval (point node) := by
  simp [consistencyDiscrepancy, Polynomial.eval_sub, Polynomial.eval_mul,
    packing_vanishing_eval_at_node nodes point node nodeMembership]

/--
If one batched nonlinear constraint fails on the packing domain, no claimed quotient and mask can
make the cross-multiplied consistency polynomial identically zero.
-/
theorem consistency_discrepancy_ne_zero_of_batch_failure
    [DecidableEq Node]
    (nodes : Finset Node)
    (point : Node -> F)
    (batched claimedQuotient maskedPolynomial : F[X])
    (node : Node)
    (nodeMembership : node ∈ nodes)
    (batchFailure : batched.eval (point node) ≠ 0) :
    consistencyDiscrepancy nodes point batched claimedQuotient maskedPolynomial ≠ 0 := by
  intro discrepancyZero
  have evaluatedZero :
      (consistencyDiscrepancy nodes point
          batched claimedQuotient maskedPolynomial).eval (point node) = 0 := by
    rw [discrepancyZero]
    exact Polynomial.eval_zero
  rw [consistency_discrepancy_eval_at_node
    nodes point batched claimedQuotient maskedPolynomial node nodeMembership] at evaluatedZero
  exact batchFailure (neg_eq_zero.mp evaluatedZero)

/-- A product of one linear factor per packing node has degree at most the node count. -/
theorem packing_vanishing_natDegree_le
    [DecidableEq Node]
    (nodes : Finset Node)
    (point : Node -> F) :
    (packingVanishing nodes point).natDegree ≤ nodes.card := by
  classical
  calc
    (packingVanishing nodes point).natDegree ≤
        ∑ node ∈ nodes, (X - C (point node)).natDegree := by
      unfold packingVanishing
      exact Polynomial.natDegree_prod_le nodes (fun node => X - C (point node))
    _ = nodes.card := by
      simp

/--
Generic degree bound for the cross-multiplied verifier equation.  It records separately the
packing-domain degree, the claimed quotient/mask degree, and the batched-constraint degree.
-/
theorem consistency_discrepancy_natDegree_le
    [DecidableEq Node]
    (nodes : Finset Node)
    (point : Node -> F)
    (batched claimedQuotient maskedPolynomial : F[X])
    (packingDegree quotientDegree totalDegree : Nat)
    (packingBound : nodes.card ≤ packingDegree)
    (claimedBound : claimedQuotient.natDegree ≤ quotientDegree)
    (maskBound : maskedPolynomial.natDegree ≤ quotientDegree)
    (batchedBound : batched.natDegree ≤ totalDegree)
    (productBound : packingDegree + quotientDegree ≤ totalDegree) :
    (consistencyDiscrepancy nodes point batched claimedQuotient maskedPolynomial).natDegree ≤
      totalDegree := by
  have differenceBound :
      (claimedQuotient - maskedPolynomial).natDegree ≤ quotientDegree :=
    (Polynomial.natDegree_sub_le claimedQuotient maskedPolynomial).trans
      (max_le claimedBound maskBound)
  have vanishingBound :
      (packingVanishing nodes point).natDegree ≤ packingDegree :=
    (packing_vanishing_natDegree_le nodes point).trans packingBound
  have multiplicationBound :
      (packingVanishing nodes point *
          (claimedQuotient - maskedPolynomial)).natDegree ≤ totalDegree := by
    exact Polynomial.natDegree_mul_le.trans
      ((Nat.add_le_add vanishingBound differenceBound).trans productBound)
  exact
    (Polynomial.natDegree_sub_le
      (packingVanishing nodes point * (claimedQuotient - maskedPolynomial))
      batched).trans
      (max_le multiplicationBound batchedBound)

section FiniteSampling

variable [Fintype F] [DecidableEq F] [DecidableEq Node]

omit [Field F] [Fintype F] [DecidableEq Node] in
/-- An injective packing map preserves the exact number of excluded field points. -/
theorem packing_point_set_card
    (nodes : Finset Node)
    (point : Node -> F)
    (pointInjective : Set.InjOn point nodes) :
    (packingPointSet nodes point).card = nodes.card := by
  exact Finset.card_image_iff.mpr pointInjective

omit [Field F] [DecidableEq Node] in
/-- Exact cardinality of the field after excluding the packing domain. -/
theorem outside_packing_domain_card
    (nodes : Finset Node)
    (point : Node -> F) :
    (outsidePackingDomain nodes point).card =
      Fintype.card F - (packingPointSet nodes point).card := by
  calc
    (outsidePackingDomain nodes point).card =
        (Finset.univ : Finset F).card -
          ((packingPointSet nodes point) ∩ Finset.univ).card := by
      exact Finset.card_sdiff
    _ = Fintype.card F - (packingPointSet nodes point).card := by
      simp

omit [DecidableEq Node] in
/--
Uniformly sampling a fixed-size subset of valid opening points hits only roots of a nonzero
degree-bounded polynomial with the exact restricted-domain hypergeometric bound.
-/
theorem uniform_roots_outside_packing_probability_le
    (nodes : Finset Node)
    (point : Node -> F)
    (polynomial : F[X])
    (polynomialNonzero : polynomial ≠ 0)
    (sampleSize degreeBound : Nat)
    (degreeBounded : polynomial.natDegree ≤ degreeBound)
    (sampleFits :
      sampleSize ≤ Fintype.card F - (packingPointSet nodes point).card) :
    uniformBadSubsetProbability
        (outsidePackingDomain nodes point)
        (rootsOutsidePacking nodes point polynomial)
        sampleSize ≤
      (Nat.choose degreeBound sampleSize : Rat) /
        Nat.choose
          (Fintype.card F - (packingPointSet nodes point).card)
          sampleSize := by
  have badSubset :
      rootsOutsidePacking nodes point polynomial ⊆
        outsidePackingDomain nodes point :=
    Finset.inter_subset_right
  have badCardBound :
      (rootsOutsidePacking nodes point polynomial).card ≤ degreeBound := by
    exact (Finset.card_le_card Finset.inter_subset_left).trans
      ((root_set_card_le_nat_degree polynomialNonzero).trans degreeBounded)
  have sampleFitsAmbient :
      sampleSize ≤ (outsidePackingDomain nodes point).card := by
    rwa [outside_packing_domain_card]
  have bound := uniform_bad_subset_probability_le
    badSubset badCardBound sampleFitsAmbient
  simpa [outside_packing_domain_card] using bound

end FiniteSampling

section ActiveGoldilocks

variable [DecidableEq Node]

/-- Active profile degree bound for the exact cross-multiplied production verifier equation. -/
theorem active_consistency_discrepancy_natDegree_le
    (nodes : Finset Node)
    (point : Node -> Goldilocks)
    (batched claimedQuotient maskedPolynomial : Goldilocks[X])
    (nodesCard : nodes.card = activePackingFactor)
    (claimedBound :
      claimedQuotient.natDegree ≤ activeConstraintPolynomialDegree)
    (maskBound :
      maskedPolynomial.natDegree ≤ activeConstraintPolynomialDegree)
    (batchedBound :
      batched.natDegree ≤ activeBatchedConstraintPolynomialDegree) :
    (consistencyDiscrepancy nodes point batched claimedQuotient maskedPolynomial).natDegree ≤
      activePiopConsistencyDiscrepancyDegree := by
  apply consistency_discrepancy_natDegree_le nodes point
    batched claimedQuotient maskedPolynomial
    activePackingFactor activeConstraintPolynomialDegree
    activePiopConsistencyDiscrepancyDegree
  · exact nodesCard.le
  · exact claimedBound
  · exact maskBound
  · simpa [activePiopConsistencyDiscrepancyDegree] using batchedBound
  · decide

/--
Concrete third SmallWood term.  For a false nonlinear batch, five uniform distinct valid opening
points all satisfy the forged quotient equation with probability at most epsilon3.
-/
theorem active_false_batch_opening_probability_le
    (nodes : Finset Node)
    (point : Node -> Goldilocks)
    (pointInjective : Set.InjOn point nodes)
    (batched claimedQuotient maskedPolynomial : Goldilocks[X])
    (node : Node)
    (nodeMembership : node ∈ nodes)
    (nodesCard : nodes.card = activePackingFactor)
    (batchFailure : batched.eval (point node) ≠ 0)
    (claimedBound :
      claimedQuotient.natDegree ≤ activeConstraintPolynomialDegree)
    (maskBound :
      maskedPolynomial.natDegree ≤ activeConstraintPolynomialDegree)
    (batchedBound :
      batched.natDegree ≤ activeBatchedConstraintPolynomialDegree) :
    uniformBadSubsetProbability
        (outsidePackingDomain nodes point)
        (rootsOutsidePacking nodes point
          (consistencyDiscrepancy nodes point
            batched claimedQuotient maskedPolynomial))
        activeProfile.nbOpenedEvals ≤
      (epsilon3Numerator : Rat) / epsilon3Denominator := by
  let discrepancy :=
    consistencyDiscrepancy nodes point batched claimedQuotient maskedPolynomial
  have discrepancyNonzero : discrepancy ≠ 0 :=
    consistency_discrepancy_ne_zero_of_batch_failure
      nodes point batched claimedQuotient maskedPolynomial
      node nodeMembership batchFailure
  have discrepancyDegree :
      discrepancy.natDegree ≤ activePiopConsistencyDiscrepancyDegree :=
    active_consistency_discrepancy_natDegree_le
      nodes point batched claimedQuotient maskedPolynomial
      nodesCard claimedBound maskBound batchedBound
  have packingCard :
      (packingPointSet nodes point).card = activePackingFactor := by
    rw [packing_point_set_card nodes point pointInjective, nodesCard]
  have ambientCard :
      Fintype.card Goldilocks - (packingPointSet nodes point).card =
        activePiopOpeningDomainSize := by
    rw [packingCard]
    simp [activePiopOpeningDomainSize, goldilocksOrder,
      Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus]
  have sampleFits :
      activeProfile.nbOpenedEvals ≤
        Fintype.card Goldilocks - (packingPointSet nodes point).card := by
    rw [ambientCard]
    decide
  calc
    uniformBadSubsetProbability
        (outsidePackingDomain nodes point)
        (rootsOutsidePacking nodes point discrepancy)
        activeProfile.nbOpenedEvals ≤
      (Nat.choose activePiopConsistencyDiscrepancyDegree
          activeProfile.nbOpenedEvals : Rat) /
        Nat.choose
          (Fintype.card Goldilocks - (packingPointSet nodes point).card)
          activeProfile.nbOpenedEvals :=
      uniform_roots_outside_packing_probability_le
        nodes point discrepancy discrepancyNonzero
        activeProfile.nbOpenedEvals activePiopConsistencyDiscrepancyDegree
        discrepancyDegree sampleFits
    _ =
      (Nat.choose activePiopConsistencyDiscrepancyDegree
          activeProfile.nbOpenedEvals : Rat) /
        Nat.choose activePiopOpeningDomainSize
          activeProfile.nbOpenedEvals := by
      rw [ambientCard]
    _ = (epsilon3Numerator : Rat) / epsilon3Denominator :=
      active_epsilon3_is_uniform_root_subset_bound.symm

end ActiveGoldilocks

end

end HegemonCrypto.SmallWood.PiopEvaluation
