import HegemonCrypto.SmallWoodProductionPolynomials

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Exact production PIOP semantics

This module formalizes the polynomial objects constructed and checked by the active production
PIOP.  It is intentionally separate from the generated constraint-program certificate so routine
PIOP changes do not force Lean to re-elaborate that large static artifact.
-/

namespace HegemonCrypto.SmallWood.ProductionPiop

open Polynomial
open HegemonCrypto.FiniteFieldSampling
open HegemonCrypto.SmallWood.Interactive
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.PiopEvaluation
open HegemonCrypto.SmallWood.PiopExtraction
open HegemonCrypto.SmallWood.PiopOpeningSampling
open HegemonCrypto.SmallWood.ProductionPolynomials
open HegemonCrypto.SmallWoodPowerBatching
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWoodTranscript
open HegemonCrypto.UniformSubsetSampling
open Hegemon.Transaction.SmallWoodNoGrindingSoundness
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

noncomputable section

/-- Interpret one fixed-width native coefficient vector as a Goldilocks polynomial. -/
def fieldWordPolynomial
    {degree : Nat}
    (coefficients : Fin (degree + 1) -> FieldWord) : Goldilocks[X] :=
  ∑ coefficient : Fin (degree + 1),
    C (wordToGoldilocks (coefficients coefficient)) * X ^ coefficient.val

theorem field_word_polynomial_degree_le
    {degree : Nat}
    (coefficients : Fin (degree + 1) -> FieldWord) :
    (fieldWordPolynomial coefficients).natDegree ≤ degree := by
  unfold fieldWordPolynomial
  apply natDegree_sum_le_of_forall_le
  intro coefficient _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_C, natDegree_X_pow, zero_add]
  omega

/-- Canonical field-word coefficients of one Goldilocks polynomial up to a fixed degree. -/
def polynomialFieldWords
    {degree : Nat}
    (polynomial : Goldilocks[X]) :
    Fin (degree + 1) -> FieldWord :=
  fun coefficient =>
    fieldWordGoldilocksEquiv.symm (polynomial.coeff coefficient.val)

/-- A degree-bounded polynomial is exactly recovered from all of its canonical coefficients. -/
theorem field_word_polynomial_polynomialFieldWords
    {degree : Nat}
    (polynomial : Goldilocks[X])
    (degreeBound : polynomial.natDegree ≤ degree) :
    fieldWordPolynomial (polynomialFieldWords (degree := degree) polynomial) =
      polynomial := by
  unfold fieldWordPolynomial polynomialFieldWords
  have roundtrip (value : Goldilocks) :
      wordToGoldilocks (fieldWordGoldilocksEquiv.symm value) = value :=
    fieldWordGoldilocksEquiv.apply_symm_apply value
  simp_rw [roundtrip]
  rw [Fin.sum_univ_eq_sum_range
    (fun index =>
      C (polynomial.coeff index) * X ^ index)]
  exact
    (polynomial.as_sum_range_C_mul_X_pow'
      (Nat.lt_succ_iff.mpr degreeBound)).symm

/-- Typed interactive PIOP message obtained from the exact reconstructed native polynomials. -/
def piopPolynomialMessageOf
    (nonlinear :
      Fin rho -> Goldilocks[X])
    (linear :
      Fin rho -> Goldilocks[X]) :
    PiopPolynomialMessage where
  nonlinear := fun repetition =>
    polynomialFieldWords
      (degree := nonlinearMaskPolynomialDegree)
      (nonlinear repetition)
  linear := fun repetition =>
    polynomialFieldWords
      (degree := linearMaskPolynomialDegree)
      (linear repetition)

/-- Claimed degree-480 nonlinear quotient-plus-mask polynomial sent in one PIOP repetition. -/
def claimedNonlinearPolynomial
    (message : PiopPolynomialMessage)
    (repetition : Fin rho) : Goldilocks[X] :=
  fieldWordPolynomial (message.nonlinear repetition)

/-- Claimed degree-131 linear batch-plus-mask polynomial sent in one PIOP repetition. -/
def claimedLinearPolynomial
    (message : PiopPolynomialMessage)
    (repetition : Fin rho) : Goldilocks[X] :=
  fieldWordPolynomial (message.linear repetition)

theorem claimed_nonlinear_polynomial_piopPolynomialMessageOf
    (nonlinear linear : Fin rho -> Goldilocks[X])
    (degreeBound :
      ∀ repetition,
        (nonlinear repetition).natDegree ≤
          nonlinearMaskPolynomialDegree)
    (repetition : Fin rho) :
    claimedNonlinearPolynomial
        (piopPolynomialMessageOf nonlinear linear) repetition =
      nonlinear repetition :=
  field_word_polynomial_polynomialFieldWords
    (nonlinear repetition) (degreeBound repetition)

theorem claimed_linear_polynomial_piopPolynomialMessageOf
    (nonlinear linear : Fin rho -> Goldilocks[X])
    (degreeBound :
      ∀ repetition,
        (linear repetition).natDegree ≤
          linearMaskPolynomialDegree)
    (repetition : Fin rho) :
    claimedLinearPolynomial
        (piopPolynomialMessageOf nonlinear linear) repetition =
      linear repetition :=
  field_word_polynomial_polynomialFieldWords
    (linear repetition) (degreeBound repetition)

theorem claimed_nonlinear_polynomial_degree_le
    (message : PiopPolynomialMessage)
    (repetition : Fin rho) :
    (claimedNonlinearPolynomial message repetition).natDegree ≤
      nonlinearMaskPolynomialDegree :=
  field_word_polynomial_degree_le _

theorem claimed_linear_polynomial_degree_le
    (message : PiopPolynomialMessage)
    (repetition : Fin rho) :
    (claimedLinearPolynomial message repetition).natDegree ≤
      linearMaskPolynomialDegree :=
  field_word_polynomial_degree_le _

/-- Embed a real nonlinear-constraint coordinate in the padded production challenge row. -/
def nonlinearChallengeIndex
    (statement : Statement)
    (constraint : Fin statement.nonlinearConstraintCount) :
    Fin (productionPiopRowWidth
      statement.nonlinearConstraintCount statement.linearConstraintCount) :=
  ⟨constraint.val,
    constraint.isLt.trans_le
      (Nat.le_max_left
        statement.nonlinearConstraintCount statement.linearConstraintCount)⟩

/--
The exact nonlinear batch constructed by `piop_run` before division by the packing vanishing
polynomial. Padding coordinates are absent because their production polynomial is identically zero.
-/
def productionNonlinearBatch
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (repetition : Fin rho) : Goldilocks[X] :=
  ∑ constraint : Fin statement.nonlinearConstraintCount,
    C (wordToGoldilocks
        (challenge repetition (nonlinearChallengeIndex statement constraint))) *
      productionNonlinearPolynomial statement oracle constraint.val

theorem production_nonlinear_batch_degree_le
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (challenge : PiopBatchingChallenge statement)
    (repetition : Fin rho) :
    (productionNonlinearBatch statement oracle challenge repetition).natDegree ≤
      effectiveConstraintDegree * witnessPolynomialDegree := by
  have countEquation :
      statement.nonlinearConstraintCount = nonlinearConstraintCount :=
    active.2.2.2.1
  unfold productionNonlinearBatch
  refine natDegree_sum_le_of_forall_le Finset.univ _ ?_
  intro constraint _
  have constraintBound : constraint.val < nonlinearConstraintCount := by
    simpa [countEquation] using constraint.isLt
  refine natDegree_mul_le.trans ?_
  simpa only [natDegree_C, zero_add] using
    production_nonlinear_polynomial_degree_le
      statement oracle constraint.val constraintBound

/--
At every packing point the exact polynomial batch is the verifier challenge's dot product with the
generated production constraint values.
-/
theorem production_nonlinear_batch_at_packing_point
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (challenge : PiopBatchingChallenge statement)
    (repetition : Fin rho)
    (lane : Nat)
    (laneBound : lane < statement.lppcPackingFactor) :
    (productionNonlinearBatch statement oracle challenge repetition).eval
        (packingNodePoint lane) =
      ∑ constraint : Fin statement.nonlinearConstraintCount,
        wordToGoldilocks
            (challenge repetition (nonlinearChallengeIndex statement constraint)) *
          toGoldilocks
            (nonlinearConstraintValue statement (extractWitness oracle)
              lane constraint.val) := by
  unfold productionNonlinearBatch
  rw [eval_finsetSum]
  apply Finset.sum_congr rfl
  intro constraint _
  rw [eval_mul, eval_C,
    production_nonlinear_polynomial_at_packing_point
      statement oracle active constraint.val lane constraint.isLt laneBound]

/-- Cross-multiplied nonlinear equation checked at the five PIOP opening points. -/
def productionNonlinearDiscrepancy
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (repetition : Fin rho) : Goldilocks[X] :=
  consistencyDiscrepancy
    (Finset.range statement.lppcPackingFactor)
    packingNodePoint
    (productionNonlinearBatch statement oracle challenge repetition)
    (claimedNonlinearPolynomial message repetition)
    (nonlinearMaskPolynomial oracle repetition)

theorem production_nonlinear_discrepancy_degree_le
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (repetition : Fin rho) :
    (productionNonlinearDiscrepancy
      statement oracle challenge message repetition).natDegree ≤
        activePiopConsistencyDiscrepancyDegree := by
  unfold productionNonlinearDiscrepancy
  apply active_consistency_discrepancy_natDegree_le
  · rw [Finset.card_range, active.2.1]
    rfl
  · exact claimed_nonlinear_polynomial_degree_le message repetition
  · exact nonlinear_mask_polynomial_degree_le oracle repetition
  · simpa [
      activeBatchedConstraintPolynomialDegree,
      activeConstraintDegree,
      activeWitnessPolynomialDegree,
      effectiveConstraintDegree,
      witnessPolynomialDegree,
      activePackingFactor,
      packingFactor,
      Hegemon.Transaction.SmallWoodTranscriptBinding.activeProfile,
      HegemonCrypto.SmallWoodTranscript.activeParameters,
      openedEvaluations
    ] using
      production_nonlinear_batch_degree_le
        statement oracle active challenge repetition

/-! ## Exact sparse linear polynomials -/

/-- Sparse-table witness index used by one production linear term. -/
def productionLinearTermIndex
    (statement : Statement)
    (term : Nat) : Nat :=
  statement.linearTermIndices.getD term 0

/-- Sparse-table coefficient used by one production linear term. -/
def productionLinearTermCoefficient
    (statement : Statement)
    (term : Nat) : Goldilocks :=
  toGoldilocks (statement.linearTermCoefficients.getD term 0)

/--
Exact polynomial contributed by one Rust sparse linear term:
`coefficient * witnessPolynomial[row] * packingLagrangeBasis[lane]`.
-/
def productionLinearTermPolynomial
    (statement : Statement)
    (oracle : CommittedOracle)
    (term : Nat) : Goldilocks[X] :=
  C (productionLinearTermCoefficient statement term) *
      extractedWitnessPolynomialAt oracle
        (productionLinearTermIndex statement term / packingFactor) *
    Lagrange.basis
      (Finset.range packingFactor)
      packingNodePoint
      (productionLinearTermIndex statement term % packingFactor)

theorem production_linear_term_polynomial_degree_le
    (statement : Statement)
    (oracle : CommittedOracle)
    (term : Nat) :
    (productionLinearTermPolynomial statement oracle term).natDegree ≤
      linearMaskPolynomialDegree := by
  have laneMembership :
      productionLinearTermIndex statement term % packingFactor ∈
        Finset.range packingFactor :=
    Finset.mem_range.mpr (Nat.mod_lt _ (by decide))
  have basisDegree :
      (Lagrange.basis
          (Finset.range packingFactor)
          packingNodePoint
          (productionLinearTermIndex statement term % packingFactor)).natDegree =
        packingFactor - 1 := by
    rw [Lagrange.natDegree_basis packing_node_point_injective laneMembership,
      Finset.card_range]
  have coefficientWitnessDegree :
      (C (productionLinearTermCoefficient statement term) *
          extractedWitnessPolynomialAt oracle
            (productionLinearTermIndex statement term / packingFactor)).natDegree ≤
        witnessPolynomialDegree := by
    refine natDegree_mul_le.trans ?_
    simpa only [natDegree_C, zero_add] using
      extracted_witness_polynomial_at_degree_le oracle
        (productionLinearTermIndex statement term / packingFactor)
  unfold productionLinearTermPolynomial
  calc
    (C (productionLinearTermCoefficient statement term) *
          extractedWitnessPolynomialAt oracle
            (productionLinearTermIndex statement term / packingFactor) *
        Lagrange.basis
          (Finset.range packingFactor)
          packingNodePoint
          (productionLinearTermIndex statement term % packingFactor)).natDegree ≤
        (C (productionLinearTermCoefficient statement term) *
            extractedWitnessPolynomialAt oracle
              (productionLinearTermIndex statement term / packingFactor)).natDegree +
          (Lagrange.basis
            (Finset.range packingFactor)
            packingNodePoint
            (productionLinearTermIndex statement term % packingFactor)).natDegree :=
      natDegree_mul_le
    _ ≤ witnessPolynomialDegree + (packingFactor - 1) :=
      Nat.add_le_add coefficientWitnessDegree basisDegree.le
    _ = linearMaskPolynomialDegree := by
      rfl

/-- Summing one sparse term over all packing nodes selects exactly its encoded witness lane. -/
theorem production_linear_term_polynomial_node_sum
    (statement : Statement)
    (oracle : CommittedOracle)
    (term : Nat) :
    nodeSum
        (Finset.range packingFactor)
        packingNodePoint
        (productionLinearTermPolynomial statement oracle term) =
      productionLinearTermCoefficient statement term *
        (extractedWitnessPolynomialAt oracle
          (productionLinearTermIndex statement term / packingFactor)).eval
            (packingNodePoint
              (productionLinearTermIndex statement term % packingFactor)) := by
  classical
  have laneMembership :
      productionLinearTermIndex statement term % packingFactor ∈
        Finset.range packingFactor :=
    Finset.mem_range.mpr (Nat.mod_lt _ (by decide))
  unfold nodeSum productionLinearTermPolynomial
  rw [Finset.sum_eq_single
    (productionLinearTermIndex statement term % packingFactor)]
  · simp only [eval_mul, eval_C,
      Lagrange.eval_basis_self packing_node_point_injective laneMembership,
      mul_one]
  · intro other otherMembership otherNe
    rw [eval_mul, Lagrange.eval_basis_of_ne otherNe.symm otherMembership, mul_zero]
  · exact fun outside => (outside laneMembership).elim

/-- One sparse term's packing sum is its coefficient times the canonical extracted witness cell. -/
theorem production_linear_term_polynomial_node_sum_eq_cell
    (statement : Statement)
    (oracle : CommittedOracle)
    (term : Nat) :
    nodeSum
        (Finset.range packingFactor)
        packingNodePoint
        (productionLinearTermPolynomial statement oracle term) =
      productionLinearTermCoefficient statement term *
        toGoldilocks
          ((extractWitness oracle).getD
            (productionLinearTermIndex statement term) 0) := by
  rw [production_linear_term_polynomial_node_sum,
    extracted_witness_polynomial_at_flat_index]

/-- Exact sparse polynomial for one production linear constraint. -/
def productionLinearConstraintPolynomial
    (statement : Statement)
    (oracle : CommittedOracle)
    (constraint : Nat) : Goldilocks[X] :=
  let start := statement.linearTermOffsets.getD constraint 0
  let stop := statement.linearTermOffsets.getD (constraint + 1) start
  ∑ relativeTerm ∈ Finset.range (stop - start),
    productionLinearTermPolynomial statement oracle (start + relativeTerm)

/-- Exact field sum of one sparse linear constraint over the extracted row-major witness. -/
def productionLinearConstraintCellSum
    (statement : Statement)
    (oracle : CommittedOracle)
    (constraint : Nat) : Goldilocks :=
  let start := statement.linearTermOffsets.getD constraint 0
  let stop := statement.linearTermOffsets.getD (constraint + 1) start
  ∑ relativeTerm ∈ Finset.range (stop - start),
    productionLinearTermCoefficient statement (start + relativeTerm) *
      toGoldilocks
        ((extractWitness oracle).getD
          (productionLinearTermIndex statement (start + relativeTerm)) 0)

theorem production_linear_constraint_polynomial_degree_le
    (statement : Statement)
    (oracle : CommittedOracle)
    (constraint : Nat) :
    (productionLinearConstraintPolynomial statement oracle constraint).natDegree ≤
      linearMaskPolynomialDegree := by
  unfold productionLinearConstraintPolynomial
  apply natDegree_sum_le_of_forall_le
  intro relativeTerm _
  exact production_linear_term_polynomial_degree_le
    statement oracle _

/-- The exact Rust sparse polynomial has the expected packing-node sum. -/
theorem production_linear_constraint_polynomial_node_sum
    (statement : Statement)
    (oracle : CommittedOracle)
    (constraint : Nat) :
    nodeSum
        (Finset.range packingFactor)
        packingNodePoint
        (productionLinearConstraintPolynomial statement oracle constraint) =
      productionLinearConstraintCellSum statement oracle constraint := by
  classical
  unfold productionLinearConstraintPolynomial productionLinearConstraintCellSum nodeSum
  simp_rw [eval_finsetSum]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro relativeTerm relativeTermMembership
  simpa only [nodeSum] using
    production_linear_term_polynomial_node_sum_eq_cell
      statement oracle
      (statement.linearTermOffsets.getD constraint 0 + relativeTerm)

/-- The extracted sparse cell sum is exactly the formal production linear-constraint evaluator. -/
theorem production_linear_constraint_cell_sum_eq_value
    (statement : Statement)
    (oracle : CommittedOracle)
    (constraint : Nat) :
    productionLinearConstraintCellSum statement oracle constraint =
      toGoldilocks
        (linearConstraintValue statement (extractWitness oracle) constraint) := by
  unfold productionLinearConstraintCellSum linearConstraintValue
  let start := statement.linearTermOffsets.getD constraint 0
  let stop := statement.linearTermOffsets.getD (constraint + 1) start
  let termValue := fun relativeTerm =>
    let term := start + relativeTerm
    fieldMul (statement.linearTermCoefficients.getD term 0)
      ((extractWitness oracle).getD
        (statement.linearTermIndices.getD term 0) 0)
  change
    (∑ relativeTerm ∈ Finset.range (stop - start),
      toGoldilocks
          (statement.linearTermCoefficients.getD
            (start + relativeTerm) 0) *
        toGoldilocks
          ((extractWitness oracle).getD
            (statement.linearTermIndices.getD
              (start + relativeTerm) 0) 0)) =
      toGoldilocks
        ((List.range (stop - start)).foldl
          (fun accumulator relativeTerm =>
            fieldAdd accumulator (termValue relativeTerm)) 0)
  rw [← List.foldl_map, toGoldilocks_foldl_fieldAdd]
  simp only [toGoldilocks, Nat.cast_zero, zero_add]
  rw [List.map_map,
    ← List.sum_toFinset _ List.nodup_range,
    List.toFinset_range]
  apply Finset.sum_congr rfl
  intro relativeTerm _
  exact (toGoldilocks_fieldMul _ _).symm

/-- Exact production linear polynomial semantics, including off-domain Rust evaluation behavior. -/
theorem production_linear_constraint_polynomial_node_sum_eq_value
    (statement : Statement)
    (oracle : CommittedOracle)
    (constraint : Nat) :
    nodeSum
        (Finset.range packingFactor)
        packingNodePoint
        (productionLinearConstraintPolynomial statement oracle constraint) =
      toGoldilocks
        (linearConstraintValue statement (extractWitness oracle) constraint) := by
  rw [production_linear_constraint_polynomial_node_sum,
    production_linear_constraint_cell_sum_eq_value]

/-- Embed a real linear-constraint coordinate in the shared padded challenge row. -/
def linearChallengeIndex
    (statement : Statement)
    (constraint : Fin statement.linearConstraintCount) :
    Fin (productionPiopRowWidth
      statement.nonlinearConstraintCount statement.linearConstraintCount) :=
  ⟨constraint.val,
    constraint.isLt.trans_le
      (Nat.le_max_right
        statement.nonlinearConstraintCount statement.linearConstraintCount)⟩

/-- Exact linear polynomial batch constructed by `get_constraint_linear_polynomials_batched`. -/
def productionLinearBatch
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (repetition : Fin rho) : Goldilocks[X] :=
  ∑ constraint : Fin statement.linearConstraintCount,
    C (wordToGoldilocks
        (challenge repetition (linearChallengeIndex statement constraint))) *
      productionLinearConstraintPolynomial statement oracle constraint.val

theorem production_linear_batch_degree_le
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (repetition : Fin rho) :
    (productionLinearBatch statement oracle challenge repetition).natDegree ≤
      linearMaskPolynomialDegree := by
  unfold productionLinearBatch
  apply natDegree_sum_le_of_forall_le
  intro constraint _
  refine natDegree_mul_le.trans ?_
  simpa only [natDegree_C, zero_add] using
    production_linear_constraint_polynomial_degree_le
      statement oracle constraint.val

/-- Batched public linear target reconstructed by the production verifier. -/
def productionLinearBatchTarget
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement)
    (repetition : Fin rho) : Goldilocks :=
  ∑ constraint : Fin statement.linearConstraintCount,
    wordToGoldilocks
        (challenge repetition (linearChallengeIndex statement constraint)) *
      toGoldilocks
        (fieldValue (statement.linearTargets.getD constraint.val 0))

/-- The exact Rust linear batch sums to the challenge-weighted extracted constraint values. -/
theorem production_linear_batch_node_sum
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (repetition : Fin rho) :
    nodeSum
        (Finset.range packingFactor)
        packingNodePoint
        (productionLinearBatch statement oracle challenge repetition) =
      ∑ constraint : Fin statement.linearConstraintCount,
        wordToGoldilocks
            (challenge repetition (linearChallengeIndex statement constraint)) *
          toGoldilocks
            (linearConstraintValue
              statement (extractWitness oracle) constraint.val) := by
  change
    nodeSum
        (Finset.range packingFactor)
        packingNodePoint
        (batch
          Finset.univ
          (fun constraint : Fin statement.linearConstraintCount =>
            wordToGoldilocks
              (challenge repetition (linearChallengeIndex statement constraint)))
          (fun constraint =>
            productionLinearConstraintPolynomial
              statement oracle constraint.val)) = _
  rw [nodeSum_batch]
  apply Finset.sum_congr rfl
  intro constraint _
  rw [production_linear_constraint_polynomial_node_sum_eq_value]

/-- Exact packing-node sum of the committed linear mask in one production repetition. -/
def productionLinearMaskSum
    (oracle : CommittedOracle)
    (repetition : Fin rho) : Goldilocks :=
  nodeSum
    (Finset.range packingFactor)
    packingNodePoint
    (linearMaskPolynomial oracle repetition)

/--
The native verifier reconstructs the omitted constant coefficient so every claimed linear
polynomial has this public target sum. Native byte-level refinement must establish this predicate.
-/
def ClaimedLinearTarget
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage) : Prop :=
  ∀ repetition,
    nodeSum
        (Finset.range packingFactor)
        packingNodePoint
        (claimedLinearPolynomial message repetition) =
      productionLinearBatchTarget statement challenge repetition

/-- Exact linear verifier discrepancy at off-domain opening points. -/
def productionLinearDiscrepancy
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (repetition : Fin rho) : Goldilocks[X] :=
  claimedLinearPolynomial message repetition -
    productionLinearBatch statement oracle challenge repetition -
      linearMaskPolynomial oracle repetition

theorem production_linear_discrepancy_degree_le
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (repetition : Fin rho) :
    (productionLinearDiscrepancy
      statement oracle challenge message repetition).natDegree ≤
        linearMaskPolynomialDegree := by
  unfold productionLinearDiscrepancy
  exact
    (natDegree_sub_le _ _).trans <|
      max_le
        ((natDegree_sub_le _ _).trans <|
          max_le
            (claimed_linear_polynomial_degree_le message repetition)
            (production_linear_batch_degree_le
              statement oracle challenge repetition))
        (linear_mask_polynomial_degree_le oracle repetition)

/-- Packing-node sum of the exact linear discrepancy under the verifier-forced target equation. -/
theorem production_linear_discrepancy_node_sum
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (claimedTarget : ClaimedLinearTarget statement challenge message)
    (repetition : Fin rho) :
    nodeSum
        (Finset.range packingFactor)
        packingNodePoint
        (productionLinearDiscrepancy
          statement oracle challenge message repetition) =
      productionLinearBatchTarget statement challenge repetition -
        nodeSum
          (Finset.range packingFactor)
          packingNodePoint
          (productionLinearBatch statement oracle challenge repetition) -
      productionLinearMaskSum oracle repetition := by
  have targetEquation := claimedTarget repetition
  unfold nodeSum at targetEquation
  unfold productionLinearDiscrepancy productionLinearMaskSum nodeSum
  simp only [eval_sub, Finset.sum_sub_distrib]
  rw [targetEquation]

/--
If the exact linear batch plus its precommitted mask misses the verifier-forced public target, the
off-domain discrepancy is nonzero.
-/
theorem production_linear_discrepancy_ne_zero_of_affine_failure
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (claimedTarget : ClaimedLinearTarget statement challenge message)
    (repetition : Fin rho)
    (batchFailure :
      nodeSum
          (Finset.range packingFactor)
          packingNodePoint
          (productionLinearBatch statement oracle challenge repetition) +
          productionLinearMaskSum oracle repetition ≠
        productionLinearBatchTarget statement challenge repetition) :
    productionLinearDiscrepancy
      statement oracle challenge message repetition ≠ 0 := by
  intro discrepancyZero
  have summedZero :
      nodeSum
          (Finset.range packingFactor)
          packingNodePoint
          (productionLinearDiscrepancy
            statement oracle challenge message repetition) = 0 := by
    rw [discrepancyZero]
    simp [nodeSum]
  rw [production_linear_discrepancy_node_sum
    statement oracle challenge message claimedTarget repetition] at summedZero
  have targetMinusBatch :
      productionLinearBatchTarget statement challenge repetition -
          nodeSum
            (Finset.range packingFactor)
            packingNodePoint
            (productionLinearBatch statement oracle challenge repetition) =
        productionLinearMaskSum oracle repetition :=
    sub_eq_zero.mp summedZero
  apply batchFailure
  calc
    nodeSum
          (Finset.range packingFactor)
          packingNodePoint
          (productionLinearBatch statement oracle challenge repetition) +
        productionLinearMaskSum oracle repetition =
      nodeSum
          (Finset.range packingFactor)
          packingNodePoint
          (productionLinearBatch statement oracle challenge repetition) +
        (productionLinearBatchTarget statement challenge repetition -
          nodeSum
            (Finset.range packingFactor)
            packingNodePoint
            (productionLinearBatch statement oracle challenge repetition)) := by
      rw [targetMinusBatch]
    _ = productionLinearBatchTarget statement challenge repetition := by
      ring

/-! ## Exact ordered opening probability -/

/-- Canonical embedding of an allowed field word into the Goldilocks proof field. -/
def outsideWordGoldilocksEmbedding :
    Outside packingPoints ↪ Goldilocks where
  toFun point := wordToGoldilocks point.val
  inj' := by
    intro left right equal
    apply Subtype.ext
    exact fieldWordGoldilocksEquiv.injective equal

/-- Allowed field words at which one verifier-consistency polynomial vanishes. -/
def rootOutsideWords
    (polynomial : Goldilocks[X]) :
    Finset (Outside packingPoints) :=
  Finset.univ.filter fun point =>
    polynomial.eval (wordToGoldilocks point.val) = 0

theorem root_outside_words_card_le_natDegree
    {polynomial : Goldilocks[X]}
    (nonzero : polynomial ≠ 0) :
    (rootOutsideWords polynomial).card ≤ polynomial.natDegree := by
  have mappedSubset :
      (rootOutsideWords polynomial).map outsideWordGoldilocksEmbedding ⊆
        HegemonCrypto.FiniteFieldSampling.rootSet polynomial := by
    intro point pointMembership
    rcases Finset.mem_map.mp pointMembership with
      ⟨source, sourceMembership, rfl⟩
    apply (mem_root_set_iff polynomial _).2
    change polynomial.eval (wordToGoldilocks source.val) = 0
    simpa [rootOutsideWords] using sourceMembership
  calc
    (rootOutsideWords polynomial).card =
        ((rootOutsideWords polynomial).map
          outsideWordGoldilocksEmbedding).card :=
      (Finset.card_map _).symm
    _ ≤ (HegemonCrypto.FiniteFieldSampling.rootSet polynomial).card :=
      Finset.card_le_card mappedSubset
    _ ≤ polynomial.natDegree :=
      root_set_card_le_nat_degree nonzero

/-- Every point in the ordered verifier challenge is a root of one discrepancy polynomial. -/
def PolynomialOpeningPasses
    (polynomial : Goldilocks[X])
    (opening : PiopOpeningChallenge) : Prop :=
  ∀ index,
    polynomial.eval (wordToGoldilocks (opening.val index)) = 0

theorem polynomial_opening_passes_iff_sample_subset
    (polynomial : Goldilocks[X])
    (opening : PiopOpeningChallenge) :
    PolynomialOpeningPasses polynomial opening ↔
      opening.sample ⊆ rootOutsideWords polynomial := by
  constructor
  · intro passes point pointMembership
    rcases Finset.mem_map.mp pointMembership with
      ⟨index, _indexMembership, pointEqual⟩
    have root := passes index
    simpa [rootOutsideWords, ValidTuple.outsideEmbedding] using
      pointEqual ▸ root
  · intro subset index
    have selected :
        opening.outsideEmbedding index ∈ opening.sample := by
      simp [ValidTuple.sample]
    have root := subset selected
    simpa [rootOutsideWords, ValidTuple.outsideEmbedding] using root

/-- Ordered challenge probability is exactly the corresponding bad-subset probability. -/
theorem uniform_polynomial_opening_probability_eq
    (polynomial : Goldilocks[X]) :
    uniformEventProbability (PolynomialOpeningPasses polynomial) =
      uniformValidTupleBadProbability
        packingPoints openedEvaluations (rootOutsideWords polynomial) := by
  classical
  have eventSetEquation :
      uniformEventSet (PolynomialOpeningPasses polynomial) =
        Finset.univ.filter fun opening : PiopOpeningChallenge =>
          opening.sample ⊆ rootOutsideWords polynomial := by
    ext opening
    simp only [uniformEventSet, Finset.mem_filter, Finset.mem_univ, true_and]
    exact polynomial_opening_passes_iff_sample_subset polynomial opening
  unfold uniformEventProbability uniformValidTupleBadProbability
  rw [eventSetEquation, Fintype.card_subtype]
  rfl

/-- The active forbidden-field-word subtype is canonically the 64 packing coordinates. -/
def packingPointSubtypeEquiv :
    { point : FieldWord // point ∈ packingPoints } ≃ Fin packingFactor where
  toFun point :=
    ⟨point.val.val, by
      simpa only [packingPoints, Finset.mem_filter, Finset.mem_univ, true_and]
        using point.property⟩
  invFun lane :=
    ⟨⟨lane.val, lane.isLt.trans (by decide)⟩, by
      simp [packingPoints, lane.isLt]⟩
  left_inv point := by
    apply Subtype.ext
    apply Fin.ext
    rfl
  right_inv lane := by
    apply Fin.ext
    rfl

theorem packing_points_card :
    packingPoints.card = packingFactor := by
  rw [← Fintype.card_coe,
    Fintype.card_congr packingPointSubtypeEquiv,
    Fintype.card_fin]

theorem active_outside_word_card :
    Fintype.card (Outside packingPoints) =
      activePiopOpeningDomainSize := by
  rw [outside_card, Fintype.card_fin, packing_points_card]
  rfl

theorem active_opening_sample_fits :
    openedEvaluations ≤ Fintype.card (Outside packingPoints) := by
  rw [active_outside_word_card]
  decide

/--
Any nonzero active discrepancy of degree at most 544 passes all five ordered opening checks only
within the exact third SmallWood failure term.
-/
theorem active_polynomial_opening_probability_le
    {polynomial : Goldilocks[X]}
    (nonzero : polynomial ≠ 0)
    (degreeBounded :
      polynomial.natDegree ≤ activePiopConsistencyDiscrepancyDegree) :
    uniformEventProbability (PolynomialOpeningPasses polynomial) ≤
      (epsilon3Numerator : Rat) / epsilon3Denominator := by
  rw [uniform_polynomial_opening_probability_eq,
    uniform_valid_tuple_bad_probability_exact
      packingPoints openedEvaluations (rootOutsideWords polynomial)
      active_opening_sample_fits]
  have badCardBound :
      (rootOutsideWords polynomial).card ≤
        activePiopConsistencyDiscrepancyDegree :=
    (root_outside_words_card_le_natDegree nonzero).trans degreeBounded
  have denominatorPositive :
      (0 : Rat) <
        Nat.choose (Fintype.card (Outside packingPoints)) openedEvaluations := by
    exact_mod_cast Nat.choose_pos active_opening_sample_fits
  calc
    (Nat.choose (rootOutsideWords polynomial).card openedEvaluations : Rat) /
          Nat.choose (Fintype.card (Outside packingPoints)) openedEvaluations ≤
        (Nat.choose activePiopConsistencyDiscrepancyDegree openedEvaluations : Rat) /
          Nat.choose (Fintype.card (Outside packingPoints)) openedEvaluations := by
      apply (div_le_div_iff_of_pos_right denominatorPositive).2
      exact_mod_cast Nat.choose_le_choose openedEvaluations badCardBound
    _ =
        (Nat.choose activePiopConsistencyDiscrepancyDegree
            openedEvaluations : Rat) /
          Nat.choose activePiopOpeningDomainSize
            openedEvaluations := by
      rw [active_outside_word_card]
    _ = (epsilon3Numerator : Rat) / epsilon3Denominator :=
      active_epsilon3_is_uniform_root_subset_bound.symm

/-- All five repetitions pass the exact nonlinear PIOP opening equations. -/
def ProductionNonlinearOpeningPasses
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (opening : PiopOpeningChallenge) : Prop :=
  ∀ repetition,
    PolynomialOpeningPasses
      (productionNonlinearDiscrepancy
        statement oracle challenge message repetition)
      opening

/-- All five repetitions pass the exact sparse-linear PIOP opening equations. -/
def ProductionLinearOpeningPasses
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (opening : PiopOpeningChallenge) : Prop :=
  ∀ repetition,
    PolynomialOpeningPasses
      (productionLinearDiscrepancy
        statement oracle challenge message repetition)
      opening

/-- Complete production PIOP opening event: both nonlinear and sparse-linear equations pass. -/
def ProductionPiopOpeningPasses
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (opening : PiopOpeningChallenge) : Prop :=
  ProductionNonlinearOpeningPasses
      statement oracle challenge message opening ∧
    ProductionLinearOpeningPasses
      statement oracle challenge message opening

theorem production_nonlinear_discrepancy_ne_zero_of_batch_failure
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (repetition : Fin rho)
    (lane : Nat)
    (laneBound : lane < statement.lppcPackingFactor)
    (batchFailure :
      (productionNonlinearBatch statement oracle challenge repetition).eval
        (packingNodePoint lane) ≠ 0) :
    productionNonlinearDiscrepancy
      statement oracle challenge message repetition ≠ 0 := by
  exact consistency_discrepancy_ne_zero_of_batch_failure
    (Finset.range statement.lppcPackingFactor)
    packingNodePoint
    (productionNonlinearBatch statement oracle challenge repetition)
    (claimedNonlinearPolynomial message repetition)
    (nonlinearMaskPolynomial oracle repetition)
    lane (Finset.mem_range.mpr laneBound) batchFailure

/--
If one exact production batch is nonzero on a packing lane, no prover message can make all five
ordered opening checks pass outside epsilon3.
-/
theorem production_nonlinear_opening_probability_le_of_batch_failure
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (repetition : Fin rho)
    (lane : Nat)
    (laneBound : lane < statement.lppcPackingFactor)
    (batchFailure :
      (productionNonlinearBatch statement oracle challenge repetition).eval
        (packingNodePoint lane) ≠ 0) :
    uniformEventProbability
        (ProductionNonlinearOpeningPasses
          statement oracle challenge message) ≤
      (epsilon3Numerator : Rat) / epsilon3Denominator := by
  calc
    uniformEventProbability
          (ProductionNonlinearOpeningPasses
            statement oracle challenge message) ≤
        uniformEventProbability
          (PolynomialOpeningPasses
            (productionNonlinearDiscrepancy
              statement oracle challenge message repetition)) := by
      apply uniform_event_probability_mono
      intro opening allRepetitions
      exact allRepetitions repetition
    _ ≤ (epsilon3Numerator : Rat) / epsilon3Denominator :=
      active_polynomial_opening_probability_le
        (production_nonlinear_discrepancy_ne_zero_of_batch_failure
          statement oracle challenge message repetition lane laneBound batchFailure)
        (production_nonlinear_discrepancy_degree_le
          statement oracle active challenge message repetition)

/--
If one exact sparse-linear batch plus its precommitted mask misses the verifier-forced target, no
claimed polynomial can pass all ordered opening checks outside epsilon3.
-/
theorem production_linear_opening_probability_le_of_affine_failure
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (claimedTarget : ClaimedLinearTarget statement challenge message)
    (repetition : Fin rho)
    (batchFailure :
      nodeSum
          (Finset.range packingFactor)
          packingNodePoint
          (productionLinearBatch statement oracle challenge repetition) +
          productionLinearMaskSum oracle repetition ≠
        productionLinearBatchTarget statement challenge repetition) :
    uniformEventProbability
        (ProductionLinearOpeningPasses
          statement oracle challenge message) ≤
      (epsilon3Numerator : Rat) / epsilon3Denominator := by
  calc
    uniformEventProbability
          (ProductionLinearOpeningPasses
            statement oracle challenge message) ≤
        uniformEventProbability
          (PolynomialOpeningPasses
            (productionLinearDiscrepancy
              statement oracle challenge message repetition)) := by
      apply uniform_event_probability_mono
      intro opening allRepetitions
      exact allRepetitions repetition
    _ ≤ (epsilon3Numerator : Rat) / epsilon3Denominator :=
      active_polynomial_opening_probability_le
        (production_linear_discrepancy_ne_zero_of_affine_failure
          statement oracle challenge message claimedTarget repetition batchFailure)
        ((production_linear_discrepancy_degree_le
          statement oracle challenge message repetition).trans (by decide))

/-- Complete PIOP opening probability bound inherited from one nonlinear batch failure. -/
theorem production_piop_opening_probability_le_of_nonlinear_batch_failure
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (repetition : Fin rho)
    (lane : Nat)
    (laneBound : lane < statement.lppcPackingFactor)
    (batchFailure :
      (productionNonlinearBatch statement oracle challenge repetition).eval
        (packingNodePoint lane) ≠ 0) :
    uniformEventProbability
        (ProductionPiopOpeningPasses
          statement oracle challenge message) ≤
      (epsilon3Numerator : Rat) / epsilon3Denominator := by
  calc
    uniformEventProbability
          (ProductionPiopOpeningPasses
            statement oracle challenge message) ≤
        uniformEventProbability
          (ProductionNonlinearOpeningPasses
            statement oracle challenge message) := by
      apply uniform_event_probability_mono
      intro opening complete
      exact complete.1
    _ ≤ (epsilon3Numerator : Rat) / epsilon3Denominator :=
      production_nonlinear_opening_probability_le_of_batch_failure
        statement oracle active challenge message repetition lane laneBound batchFailure

/-- Complete PIOP opening probability bound inherited from one affine sparse-linear failure. -/
theorem production_piop_opening_probability_le_of_linear_affine_failure
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (claimedTarget : ClaimedLinearTarget statement challenge message)
    (repetition : Fin rho)
    (batchFailure :
      nodeSum
          (Finset.range packingFactor)
          packingNodePoint
          (productionLinearBatch statement oracle challenge repetition) +
          productionLinearMaskSum oracle repetition ≠
        productionLinearBatchTarget statement challenge repetition) :
    uniformEventProbability
        (ProductionPiopOpeningPasses
          statement oracle challenge message) ≤
      (epsilon3Numerator : Rat) / epsilon3Denominator := by
  calc
    uniformEventProbability
          (ProductionPiopOpeningPasses
            statement oracle challenge message) ≤
        uniformEventProbability
          (ProductionLinearOpeningPasses
            statement oracle challenge message) := by
      apply uniform_event_probability_mono
      intro opening complete
      exact complete.2
    _ ≤ (epsilon3Numerator : Rat) / epsilon3Denominator :=
      production_linear_opening_probability_le_of_affine_failure
        statement oracle challenge message claimedTarget repetition batchFailure

end

end HegemonCrypto.SmallWood.ProductionPiop
