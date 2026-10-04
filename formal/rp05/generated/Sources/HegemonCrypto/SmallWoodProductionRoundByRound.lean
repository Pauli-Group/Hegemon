import HegemonCrypto.SmallWoodProductionPiop

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Exact production round-by-round SmallWood system

This downstream module packages the already-checked production polynomials as the concrete
interactive system. It deliberately avoids a dependent refinement record: that representation
causes Lean to unfold the large generated nonlinear certificate during structure elaboration.
-/

namespace HegemonCrypto.SmallWood.ProductionRoundByRound

open Polynomial
open HegemonCrypto.SmallWood.Interactive
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.PiopExtraction
open HegemonCrypto.SmallWood.ProductionPiop
open HegemonCrypto.SmallWood.ProductionPolynomials
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWoodTranscript
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped BigOperators

noncomputable section

/--
Zero-padded nonlinear polynomial table. The named projection keeps routine batching proofs from
unfolding the generated production constraint certificate.
-/
def exactProductionNonlinearPolynomial
    (statement : Statement)
    (oracle : CommittedOracle)
    (index : Fin
      (productionPiopRowWidth
        statement.nonlinearConstraintCount statement.linearConstraintCount)) :
    Goldilocks[X] :=
  if _indexBound : index.val < statement.nonlinearConstraintCount then
    productionNonlinearPolynomial statement oracle index.val
  else
    0

/-- Zero-padded sparse-linear polynomial table used by the exact production system. -/
def exactProductionLinearPolynomial
    (statement : Statement)
    (oracle : CommittedOracle)
    (index : Fin
      (productionPiopRowWidth
        statement.nonlinearConstraintCount statement.linearConstraintCount)) :
    Goldilocks[X] :=
  if _indexBound : index.val < statement.linearConstraintCount then
    productionLinearConstraintPolynomial statement oracle index.val
  else
    0

/-- Zero-padded public sparse-linear target table used by the exact production system. -/
def exactProductionLinearTarget
    (statement : Statement)
    (index : Fin
      (productionPiopRowWidth
        statement.nonlinearConstraintCount statement.linearConstraintCount)) :
    Goldilocks :=
  if _indexBound : index.val < statement.linearConstraintCount then
    toGoldilocks (fieldValue (statement.linearTargets.getD index.val 0))
  else
    0

/--
Zero-padded production system whose polynomials are exactly those evaluated by the Rust prover.
Both constraint families share the same uniform challenge row width.
-/
def exactProductionPaddedSystem
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement) :
    System (F := Goldilocks) (Node := Nat)
      (Nonlinear := Fin
        (productionPiopRowWidth
          statement.nonlinearConstraintCount statement.linearConstraintCount))
      (Linear := Fin
        (productionPiopRowWidth
          statement.nonlinearConstraintCount statement.linearConstraintCount)) where
  nodes := Finset.range statement.lppcPackingFactor
  point := packingNodePoint
  pointInjective := active_packing_node_point_injective statement active
  nonlinearIndices := Finset.univ
  nonlinearPolynomial := exactProductionNonlinearPolynomial statement oracle
  linearIndices := Finset.univ
  linearPolynomial := exactProductionLinearPolynomial statement oracle
  linearTarget := exactProductionLinearTarget statement

@[simp] theorem exact_production_padded_system_nonlinear_polynomial
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (index : Fin
      (productionPiopRowWidth
        statement.nonlinearConstraintCount statement.linearConstraintCount)) :
    (exactProductionPaddedSystem statement oracle active).nonlinearPolynomial index =
      exactProductionNonlinearPolynomial statement oracle index := by
  rfl

@[simp] theorem exact_production_padded_system_linear_polynomial
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (index : Fin
      (productionPiopRowWidth
        statement.nonlinearConstraintCount statement.linearConstraintCount)) :
    (exactProductionPaddedSystem statement oracle active).linearPolynomial index =
      exactProductionLinearPolynomial statement oracle index := by
  rfl

@[simp] theorem exact_production_padded_system_linear_target
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (index : Fin
      (productionPiopRowWidth
        statement.nonlinearConstraintCount statement.linearConstraintCount)) :
    (exactProductionPaddedSystem statement oracle active).linearTarget index =
      exactProductionLinearTarget statement index := by
  rfl

/-- Exact system satisfaction implies every generated production relation equation. -/
theorem exact_production_padded_system_satisfied_implies_relation
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (satisfied : FullySatisfied
      (exactProductionPaddedSystem statement oracle active)) :
    (statement, extractWitness oracle) ∈ Relation := by
  apply (extracted_production_oracles_satisfied_iff_relation
    statement oracle active).mp
  apply (padded_production_fully_satisfied_iff
    (extractedProductionOracles statement oracle active)).mp
  constructor
  · intro nonlinear node nodeMembership
    by_cases nonlinearBound :
        nonlinear.val < statement.nonlinearConstraintCount
    · have exactEquation := satisfied.1 nonlinear node nodeMembership
      have laneBound : node < statement.lppcPackingFactor :=
        Finset.mem_range.mp nodeMembership
      simp only [paddedProductionSystem, extractedProductionOracles,
        nonlinearBound, dif_pos] at ⊢
      change
        (nonlinearConstraintPolynomial
          statement (extractWitness oracle) nonlinear.val).eval
            (packingNodePoint node) = 0
      rw [nonlinear_constraint_polynomial_at_packing_node
        statement (extractWitness oracle) active nonlinear.val node laneBound]
      simpa [exactProductionPaddedSystem, exactProductionNonlinearPolynomial, nonlinearBound,
        production_nonlinear_polynomial_at_packing_point
          statement oracle active nonlinear.val node nonlinearBound laneBound]
        using exactEquation
    · simp [paddedProductionSystem, extractedProductionOracles, nonlinearBound]
  · intro linear
    by_cases linearBound : linear.val < statement.linearConstraintCount
    · have exactEquation := satisfied.2 linear
      simp only [exactProductionPaddedSystem, exactProductionLinearPolynomial,
        exactProductionLinearTarget, linearBound, dif_pos] at exactEquation
      rw [active.2.1,
        production_linear_constraint_polynomial_node_sum_eq_value] at exactEquation
      simp only [paddedProductionSystem, extractedProductionOracles,
        linearBound, dif_pos] at ⊢
      change
        nodeSum
            (Finset.range statement.lppcPackingFactor)
            packingNodePoint
            (linearConstraintPolynomial
              statement (extractWitness oracle) linear.val) =
          toGoldilocks
            (fieldValue (statement.linearTargets.getD linear.val 0))
      rw [linear_constraint_polynomial_packing_sum
        statement (extractWitness oracle) active linear.val]
      exact exactEquation
    · simp [paddedProductionSystem, extractedProductionOracles, linearBound, nodeSum]

/-- Every valid extracted witness satisfies the exact Rust production polynomial system. -/
theorem relation_implies_exact_production_padded_system_satisfied
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (relation : (statement, extractWitness oracle) ∈ Relation) :
    FullySatisfied (exactProductionPaddedSystem statement oracle active) := by
  constructor
  · intro nonlinear node nodeMembership
    by_cases nonlinearBound :
        nonlinear.val < statement.nonlinearConstraintCount
    · have laneBound : node < statement.lppcPackingFactor :=
        Finset.mem_range.mp nodeMembership
      change
        (exactProductionNonlinearPolynomial
          statement oracle nonlinear).eval (packingNodePoint node) = 0
      rw [exactProductionNonlinearPolynomial, dif_pos nonlinearBound]
      rw [production_nonlinear_polynomial_at_packing_point
        statement oracle active nonlinear.val node nonlinearBound laneBound]
      rw [relation_nonlinear_equation
        statement (extractWitness oracle) relation node laneBound
          nonlinear.val nonlinearBound]
      simp [toGoldilocks]
    · simp [exactProductionPaddedSystem, exactProductionNonlinearPolynomial, nonlinearBound]
  · intro linear
    by_cases linearBound : linear.val < statement.linearConstraintCount
    · change
        nodeSum
            (Finset.range statement.lppcPackingFactor)
            packingNodePoint
            (exactProductionLinearPolynomial statement oracle linear) =
          exactProductionLinearTarget statement linear
      rw [exactProductionLinearPolynomial, exactProductionLinearTarget,
        dif_pos linearBound, dif_pos linearBound]
      rw [active.2.1]
      rw [production_linear_constraint_polynomial_node_sum_eq_value]
      rw [relation_linear_equation
        statement (extractWitness oracle) relation linear.val linearBound]
    · simp [exactProductionPaddedSystem, exactProductionLinearPolynomial,
        exactProductionLinearTarget, linearBound, nodeSum]

/-- Exact equivalence used by the production round-by-round extractor. -/
theorem exact_production_padded_system_fully_satisfied_iff_relation
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement) :
    FullySatisfied (exactProductionPaddedSystem statement oracle active) ↔
      (statement, extractWitness oracle) ∈ Relation :=
  ⟨exact_production_padded_system_satisfied_implies_relation statement oracle active,
    relation_implies_exact_production_padded_system_satisfied statement oracle active⟩

/--
At every packing lane, the semantic padded batch and the exact Rust nonlinear batch evaluate to
the same field element.
-/
theorem extracted_padded_nonlinear_batch_eval_eq_production
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (challenge : PiopBatchingChallenge statement)
    (repetition : Fin rho)
    (lane : Nat)
    (laneBound : lane < statement.lppcPackingFactor) :
    (nonlinearBatch
        (extractedPaddedSystem statement oracle active)
        ((piopChallengeToGoldilocks statement challenge) repetition)).eval
          (packingNodePoint lane) =
      (productionNonlinearBatch statement oracle challenge repetition).eval
        (packingNodePoint lane) := by
  rw [show extractedPaddedSystem statement oracle active =
    paddedProductionSystem
      (extractedProductionOracles statement oracle active) by rfl]
  rw [padded_production_nonlinear_batch_eq, eval_finsetSum]
  rw [production_nonlinear_batch_at_packing_point
    statement oracle active challenge repetition lane laneBound]
  apply Finset.sum_congr rfl
  intro constraint _
  rw [eval_mul, eval_C]
  have polynomialEval :
      ((extractedProductionOracles
          statement oracle active).nonlinearPolynomial constraint.val).eval
            (packingNodePoint lane) =
        toGoldilocks
          (nonlinearConstraintValue
            statement (extractWitness oracle) lane constraint.val) := by
    simpa [extractedProductionOracles, goldilocksIdentityEncoding]
      using (extractedProductionOracles
        statement oracle active).nonlinearAtPackingNode
          constraint.val constraint.isLt lane laneBound
  rw [polynomialEval]
  congr 2

/--
The global sum of the semantic sparse-linear batch equals the exact Rust sparse-linear batch sum.
-/
theorem extracted_padded_linear_batch_node_sum_eq_production
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (challenge : PiopBatchingChallenge statement)
    (repetition : Fin rho) :
    nodeSum
        (Finset.range statement.lppcPackingFactor)
        packingNodePoint
        (linearBatch
          (extractedPaddedSystem statement oracle active)
          ((piopChallengeToGoldilocks statement challenge) repetition)) =
      nodeSum
        (Finset.range statement.lppcPackingFactor)
        packingNodePoint
        (productionLinearBatch statement oracle challenge repetition) := by
  rw [show extractedPaddedSystem statement oracle active =
    paddedProductionSystem
      (extractedProductionOracles statement oracle active) by rfl]
  rw [padded_production_linear_batch_eq]
  change
    nodeSum
        (Finset.range statement.lppcPackingFactor)
        packingNodePoint
        (batch
          Finset.univ
          (fun constraint : Fin statement.linearConstraintCount =>
            piopChallengeToGoldilocks statement challenge repetition
              (paddedLinearIndex statement constraint))
          (fun constraint =>
            (extractedProductionOracles
              statement oracle active).linearPolynomial constraint.val)) = _
  rw [nodeSum_batch, active.2.1, production_linear_batch_node_sum]
  apply Finset.sum_congr rfl
  intro constraint _
  have polynomialSum :
      nodeSum
          (Finset.range packingFactor)
          packingNodePoint
          ((extractedProductionOracles
            statement oracle active).linearPolynomial constraint.val) =
        toGoldilocks
          (linearConstraintValue
            statement (extractWitness oracle) constraint.val) := by
    simpa [extractedProductionOracles, goldilocksIdentityEncoding, active.2.1]
      using (extractedProductionOracles
        statement oracle active).linearPackingSum
          constraint.val constraint.isLt
  rw [polynomialSum]
  congr 2

/-- The semantic padded public target is exactly the target reconstructed by the Rust verifier. -/
theorem extracted_padded_linear_target_batch_eq_production
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (challenge : PiopBatchingChallenge statement)
    (repetition : Fin rho) :
    Finset.univ.sum (fun linear =>
        piopChallengeToGoldilocks statement challenge repetition linear *
          (extractedPaddedSystem statement oracle active).linearTarget linear) =
      productionLinearBatchTarget statement challenge repetition := by
  rw [show extractedPaddedSystem statement oracle active =
    paddedProductionSystem
      (extractedProductionOracles statement oracle active) by rfl]
  rw [padded_production_linear_target_batch_eq]
  unfold productionLinearBatchTarget
  apply Finset.sum_congr rfl
  intro constraint _
  simp [goldilocksIdentityEncoding, piopChallengeToGoldilocks,
    paddedLinearIndex, linearChallengeIndex]

end

end HegemonCrypto.SmallWood.ProductionRoundByRound
