import HegemonCrypto.Goldilocks
import HegemonCrypto.SmallWoodInteractive
import HegemonCrypto.SmallWoodPowerBatching
import HegemonCrypto.SmallWoodTranscript

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# SmallWood PIOP batching extraction

This module proves the deterministic algebra behind the second SmallWood soundness term.  For an
unsatisfied finite PIOP system, either one packing-node nonlinear residual vector or the global
linear residual vector is nonzero.  A full uniform challenge matrix can make every repeated batch
look satisfied only if every row annihilates that fixed nonzero vector.

The probability is therefore exactly bounded by `|F|^-rho` in the concrete finite matrix sample
space.  No cryptographic assumption is used here; the Fiat--Shamir/QROM transfer is separate.
-/

namespace HegemonCrypto.SmallWood.PiopExtraction

open Polynomial
open scoped BigOperators
open HegemonCrypto.SmallWood.Interactive
open HegemonCrypto.SmallWoodPowerBatching
open Hegemon.Transaction.SmallWoodNoGrindingSoundness
open Hegemon.Transaction.SmallWoodTranscriptBinding

noncomputable section

variable {F Node : Type*}
variable [Field F]

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

/-- Satisfaction when both constraint families are indexed by the complete finite coordinate set. -/
def FullySatisfied
    {width : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width)) : Prop :=
  (∀ nonlinear : Fin width, ∀ node ∈ system.nodes,
      (system.nonlinearPolynomial nonlinear).eval (system.point node) = 0) ∧
    (∀ linear : Fin width,
      nodeSum system.nodes system.point (system.linearPolynomial linear) =
        system.linearTarget linear)

/-- One row of the verifier's nonlinear uniform-matrix batch. -/
def nonlinearBatch
    {width : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width))
    (coefficients : Fin width -> F) : F[X] :=
  batch Finset.univ coefficients system.nonlinearPolynomial

/-- One row of the verifier's linear uniform-matrix batch. -/
def linearBatch
    {width : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width))
    (coefficients : Fin width -> F) : F[X] :=
  batch Finset.univ coefficients system.linearPolynomial

/--
Every repeated row passes both pre-evaluation PIOP equations: the nonlinear batch vanishes on the
packing domain and the global linear batch reaches the correspondingly batched public target.
-/
def BatchAccepts
    {width repetitions : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width))
    (matrix : CoefficientMatrix (F := F) width repetitions) : Prop :=
  ∀ repetition,
    (∀ node ∈ system.nodes,
      (nonlinearBatch system (matrix repetition)).eval (system.point node) = 0) ∧
      nodeSum system.nodes system.point
          (linearBatch system (matrix repetition)) =
        Finset.univ.sum fun linear =>
          matrix repetition linear * system.linearTarget linear

/--
Production-accurate batching acceptance with one linear-mask sum fixed before each challenge row.
The mask does not affect nonlinear packing-node equations, while the verifier's linear target
reconstruction checks `nodeSum(batch) + maskSum = batchedTarget`.
-/
def AffineBatchAccepts
    {width repetitions : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width))
    (linearMaskSum : Fin repetitions -> F)
    (matrix : CoefficientMatrix (F := F) width repetitions) : Prop :=
  ∀ repetition,
    (∀ node ∈ system.nodes,
      (nonlinearBatch system (matrix repetition)).eval (system.point node) = 0) ∧
      nodeSum system.nodes system.point
          (linearBatch system (matrix repetition)) +
          linearMaskSum repetition =
        Finset.univ.sum fun linear =>
          matrix repetition linear * system.linearTarget linear

section FiniteProbability

variable [Fintype F] [DecidableEq F]

/-- Exact finite event in which all batching rows hide an unsatisfied system. -/
noncomputable def batchFailureSet
    {width repetitions : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width)) :
    Finset (CoefficientMatrix (F := F) width repetitions) := by
  classical
  exact Finset.univ.filter (BatchAccepts system)

/-- Uniform probability of the concrete batching failure event. -/
def batchFailureProbability
    {width repetitions : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width)) : Rat :=
  (batchFailureSet (repetitions := repetitions) system).card /
    Fintype.card (CoefficientMatrix (F := F) width repetitions)

/-- Exact finite event for production batching with arbitrary precommitted linear-mask sums. -/
noncomputable def affineBatchFailureSet
    {width repetitions : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width))
    (linearMaskSum : Fin repetitions -> F) :
    Finset (CoefficientMatrix (F := F) width repetitions) := by
  classical
  exact Finset.univ.filter (AffineBatchAccepts system linearMaskSum)

/-- Uniform probability of the production-accurate affine batching event. -/
def affineBatchFailureProbability
    {width repetitions : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width))
    (linearMaskSum : Fin repetitions -> F) : Rat :=
  (affineBatchFailureSet system linearMaskSum).card /
    Fintype.card (CoefficientMatrix (F := F) width repetitions)

/-- Packing-node residual vector for one selected nonlinear failure. -/
def nonlinearResidual
    {width : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width))
    (node : Node) : Fin width -> F :=
  fun nonlinear =>
    (system.nonlinearPolynomial nonlinear).eval (system.point node)

/-- Global target residual vector for the linear family. -/
def linearResidual
    {width : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width)) :
    Fin width -> F :=
  fun linear =>
    nodeSum system.nodes system.point (system.linearPolynomial linear) -
      system.linearTarget linear

omit [Fintype F] [DecidableEq F] in
/-- A passing nonlinear batch annihilates the residual at every packing node. -/
theorem batch_accepts_implies_nonlinear_dot_zero
    {width repetitions : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width))
    (matrix : CoefficientMatrix (F := F) width repetitions)
    (accepted : BatchAccepts system matrix)
    (repetition : Fin repetitions)
    (node : Node)
    (nodeMembership : node ∈ system.nodes) :
    uniformDotProduct (nonlinearResidual system node) (matrix repetition) = 0 := by
  have batchZero := (accepted repetition).1 node nodeMembership
  calc
    uniformDotProduct (nonlinearResidual system node) (matrix repetition) =
        Finset.univ.sum fun nonlinear =>
          matrix repetition nonlinear *
            (system.nonlinearPolynomial nonlinear).eval (system.point node) := by
      apply Finset.sum_congr rfl
      intro nonlinear _
      simp [nonlinearResidual, mul_comm]
    _ =
        (nonlinearBatch system (matrix repetition)).eval (system.point node) := by
      simp [nonlinearBatch, batch, Polynomial.eval_finsetSum,
        Polynomial.eval_mul]
    _ = 0 := batchZero

omit [Fintype F] [DecidableEq F] in
/-- A passing linear batch annihilates the vector of target-equation residuals. -/
theorem batch_accepts_implies_linear_dot_zero
    {width repetitions : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width))
    (matrix : CoefficientMatrix (F := F) width repetitions)
    (accepted : BatchAccepts system matrix)
    (repetition : Fin repetitions) :
    uniformDotProduct (linearResidual system) (matrix repetition) = 0 := by
  have linearAccepted := (accepted repetition).2
  rw [linearBatch, nodeSum_batch] at linearAccepted
  change
    (Finset.univ.sum fun linear =>
      (nodeSum system.nodes system.point
          (system.linearPolynomial linear) -
        system.linearTarget linear) *
          matrix repetition linear) = 0
  calc
    (Finset.univ.sum fun linear =>
        (nodeSum system.nodes system.point
            (system.linearPolynomial linear) -
          system.linearTarget linear) *
            matrix repetition linear) =
        (Finset.univ.sum fun linear =>
          matrix repetition linear *
            nodeSum system.nodes system.point
              (system.linearPolynomial linear)) -
          Finset.univ.sum fun linear =>
            matrix repetition linear * system.linearTarget linear := by
      simp only [sub_mul, Finset.sum_sub_distrib]
      congr 1 <;>
        apply Finset.sum_congr rfl <;>
        intro linear _ <;>
        ring
    _ = 0 := sub_eq_zero.mpr linearAccepted

omit [Fintype F] [DecidableEq F] in
/-- A production affine batch forces the linear residual dot product to negate the mask sum. -/
theorem affine_batch_accepts_implies_linear_dot
    {width repetitions : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width))
    (linearMaskSum : Fin repetitions -> F)
    (matrix : CoefficientMatrix (F := F) width repetitions)
    (accepted : AffineBatchAccepts system linearMaskSum matrix)
    (repetition : Fin repetitions) :
    uniformDotProduct (linearResidual system) (matrix repetition) =
      -linearMaskSum repetition := by
  have linearAccepted := (accepted repetition).2
  rw [linearBatch, nodeSum_batch] at linearAccepted
  change
    (Finset.univ.sum fun linear =>
      (nodeSum system.nodes system.point
          (system.linearPolynomial linear) -
        system.linearTarget linear) *
          matrix repetition linear) =
      -linearMaskSum repetition
  calc
    (Finset.univ.sum fun linear =>
        (nodeSum system.nodes system.point
            (system.linearPolynomial linear) -
          system.linearTarget linear) *
            matrix repetition linear) =
        (Finset.univ.sum fun linear =>
          matrix repetition linear *
            nodeSum system.nodes system.point
              (system.linearPolynomial linear)) -
          Finset.univ.sum fun linear =>
            matrix repetition linear * system.linearTarget linear := by
      simp only [sub_mul, Finset.sum_sub_distrib]
      congr 1 <;>
        apply Finset.sum_congr rfl <;>
        intro linear _ <;>
        ring
    _ = -linearMaskSum repetition := by
      rw [← linearAccepted]
      ring

/--
If a nonlinear packing equation fails, every accepting matrix lies in the exact all-rows
annihilation event for that nonzero residual vector.
-/
theorem nonlinear_failure_event_subset
    {width repetitions : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width))
    (nonlinear : Fin width)
    (node : Node)
    (nodeMembership : node ∈ system.nodes)
    (_failure :
      (system.nonlinearPolynomial nonlinear).eval (system.point node) ≠ 0) :
    batchFailureSet (repetitions := repetitions) system ⊆
      uniformMatrixFailureSet (nonlinearResidual system node) repetitions := by
  classical
  intro matrix matrixMembership
  have accepted : BatchAccepts system matrix :=
    (Finset.mem_filter.mp matrixMembership).2
  rw [uniformMatrixFailureSet, Fintype.mem_piFinset]
  intro repetition
  simp only [uniformDotZeroSet, Finset.mem_filter, Finset.mem_univ, true_and]
  exact batch_accepts_implies_nonlinear_dot_zero
    system matrix accepted repetition node nodeMembership

/-- Nonlinear failures remain homogeneous even when the linear mask has arbitrary fixed sums. -/
theorem nonlinear_failure_affine_event_subset
    {width repetitions : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width))
    (linearMaskSum : Fin repetitions -> F)
    (nonlinear : Fin width)
    (node : Node)
    (nodeMembership : node ∈ system.nodes)
    (_failure :
      (system.nonlinearPolynomial nonlinear).eval (system.point node) ≠ 0) :
    affineBatchFailureSet system linearMaskSum ⊆
      uniformMatrixFailureSet (nonlinearResidual system node) repetitions := by
  classical
  intro matrix matrixMembership
  have accepted : AffineBatchAccepts system linearMaskSum matrix :=
    (Finset.mem_filter.mp matrixMembership).2
  rw [uniformMatrixFailureSet, Fintype.mem_piFinset]
  intro repetition
  simp only [uniformDotZeroSet, Finset.mem_filter, Finset.mem_univ, true_and]
  have batchZero := (accepted repetition).1 node nodeMembership
  calc
    uniformDotProduct (nonlinearResidual system node) (matrix repetition) =
        Finset.univ.sum fun coordinate =>
          matrix repetition coordinate *
            (system.nonlinearPolynomial coordinate).eval (system.point node) := by
      apply Finset.sum_congr rfl
      intro coordinate _
      simp [nonlinearResidual, mul_comm]
    _ =
        (nonlinearBatch system (matrix repetition)).eval (system.point node) := by
      simp [nonlinearBatch, batch, Polynomial.eval_finsetSum,
        Polynomial.eval_mul]
    _ = 0 := batchZero

/--
If a global linear equation fails, every accepting matrix lies in the exact all-rows annihilation
event for the nonzero linear residual vector.
-/
theorem linear_failure_event_subset
    {width repetitions : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width))
    (linear : Fin width)
    (_failure :
      nodeSum system.nodes system.point (system.linearPolynomial linear) ≠
        system.linearTarget linear) :
    batchFailureSet (repetitions := repetitions) system ⊆
      uniformMatrixFailureSet (linearResidual system) repetitions := by
  classical
  intro matrix matrixMembership
  have accepted : BatchAccepts system matrix :=
    (Finset.mem_filter.mp matrixMembership).2
  rw [uniformMatrixFailureSet, Fintype.mem_piFinset]
  intro repetition
  simp only [uniformDotZeroSet, Finset.mem_filter, Finset.mem_univ, true_and]
  exact batch_accepts_implies_linear_dot_zero system matrix accepted repetition

/--
With arbitrary precommitted mask sums, every accepting challenge lies in the corresponding affine
fiber of the same nonzero linear residual.
-/
theorem linear_failure_affine_event_subset
    {width repetitions : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width))
    (linearMaskSum : Fin repetitions -> F)
    (linear : Fin width)
    (_failure :
      nodeSum system.nodes system.point (system.linearPolynomial linear) ≠
        system.linearTarget linear) :
    affineBatchFailureSet system linearMaskSum ⊆
      uniformAffineMatrixFailureSet
        (linearResidual system) (fun repetition => -linearMaskSum repetition) := by
  classical
  intro matrix matrixMembership
  have accepted : AffineBatchAccepts system linearMaskSum matrix :=
    (Finset.mem_filter.mp matrixMembership).2
  rw [uniformAffineMatrixFailureSet, Fintype.mem_piFinset]
  intro repetition
  simp only [uniformDotFiberSet, Finset.mem_filter, Finset.mem_univ, true_and]
  exact affine_batch_accepts_implies_linear_dot
    system linearMaskSum matrix accepted repetition

/--
Concrete PIOP batching soundness.  If the indexed system is unsatisfied, the exact finite failure
probability over the full uniform matrix is at most `|F|^-repetitions`.
-/
theorem unsatisfied_batch_failure_probability_le
    {width repetitions : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width))
    (unsatisfied : ¬ FullySatisfied system) :
    batchFailureProbability (repetitions := repetitions) system ≤
      ((1 : Rat) / Fintype.card F) ^ repetitions := by
  classical
  unfold FullySatisfied at unsatisfied
  by_cases nonlinearSatisfied :
      ∀ nonlinear : Fin width, ∀ node ∈ system.nodes,
        (system.nonlinearPolynomial nonlinear).eval (system.point node) = 0
  · have linearFailure :
        ¬ ∀ linear : Fin width,
          nodeSum system.nodes system.point (system.linearPolynomial linear) =
            system.linearTarget linear := by
      intro linearSatisfied
      exact unsatisfied ⟨nonlinearSatisfied, linearSatisfied⟩
    push Not at linearFailure
    obtain ⟨linear, failure⟩ := linearFailure
    have residualNonzero :
        ∃ coordinate, linearResidual system coordinate ≠ 0 :=
      ⟨linear, by
        simpa [linearResidual] using
          (sub_ne_zero.mpr failure)⟩
    let total :=
      Fintype.card (CoefficientMatrix (F := F) width repetitions)
    have totalPositive : (0 : Rat) < total := by
      exact_mod_cast Fintype.card_pos
    calc
      batchFailureProbability (repetitions := repetitions) system =
          (batchFailureSet (repetitions := repetitions) system).card / total := rfl
      _ ≤
          (uniformMatrixFailureSet
            (linearResidual system) repetitions).card / total := by
        apply (div_le_div_iff_of_pos_right totalPositive).2
        exact_mod_cast Finset.card_le_card
          (linear_failure_event_subset system linear failure)
      _ = uniformMatrixFailureProbability
          (linearResidual system) repetitions := rfl
      _ = independentUniformMatrixFailureProbability
          (linearResidual system) repetitions :=
        uniform_matrix_failure_probability_eq_independent _ _
      _ = ((1 : Rat) / Fintype.card F) ^ repetitions :=
        independent_uniform_matrix_failure_probability_exact
          residualNonzero repetitions
  · push Not at nonlinearSatisfied
    obtain ⟨nonlinear, node, nodeMembership, failure⟩ := nonlinearSatisfied
    have residualNonzero :
        ∃ coordinate, nonlinearResidual system node coordinate ≠ 0 :=
      ⟨nonlinear, failure⟩
    let total :=
      Fintype.card (CoefficientMatrix (F := F) width repetitions)
    have totalPositive : (0 : Rat) < total := by
      exact_mod_cast Fintype.card_pos
    calc
      batchFailureProbability (repetitions := repetitions) system =
          (batchFailureSet (repetitions := repetitions) system).card / total := rfl
      _ ≤
          (uniformMatrixFailureSet
            (nonlinearResidual system node) repetitions).card / total := by
        apply (div_le_div_iff_of_pos_right totalPositive).2
        exact_mod_cast Finset.card_le_card
          (nonlinear_failure_event_subset
            system nonlinear node nodeMembership failure)
      _ = uniformMatrixFailureProbability
          (nonlinearResidual system node) repetitions := rfl
      _ = independentUniformMatrixFailureProbability
          (nonlinearResidual system node) repetitions :=
        uniform_matrix_failure_probability_eq_independent _ _
      _ = ((1 : Rat) / Fintype.card F) ^ repetitions :=
        independent_uniform_matrix_failure_probability_exact
          residualNonzero repetitions

/--
Production-accurate PIOP batching soundness. Arbitrary linear-mask sums fixed before the uniform
challenge only translate the relevant fibers; they do not change the exact `|F|^-repetitions`
failure probability.
-/
theorem unsatisfied_affine_batch_failure_probability_le
    {width repetitions : Nat}
    (system :
      System (F := F) (Node := Node)
        (Nonlinear := Fin width) (Linear := Fin width))
    (linearMaskSum : Fin repetitions -> F)
    (unsatisfied : ¬ FullySatisfied system) :
    affineBatchFailureProbability system linearMaskSum ≤
      ((1 : Rat) / Fintype.card F) ^ repetitions := by
  classical
  unfold FullySatisfied at unsatisfied
  by_cases nonlinearSatisfied :
      ∀ nonlinear : Fin width, ∀ node ∈ system.nodes,
        (system.nonlinearPolynomial nonlinear).eval (system.point node) = 0
  · have linearFailure :
        ¬ ∀ linear : Fin width,
          nodeSum system.nodes system.point (system.linearPolynomial linear) =
            system.linearTarget linear := by
      intro linearSatisfied
      exact unsatisfied ⟨nonlinearSatisfied, linearSatisfied⟩
    push Not at linearFailure
    obtain ⟨linear, failure⟩ := linearFailure
    have residualNonzero :
        ∃ coordinate, linearResidual system coordinate ≠ 0 :=
      ⟨linear, by
        simpa [linearResidual] using
          (sub_ne_zero.mpr failure)⟩
    let total :=
      Fintype.card (CoefficientMatrix (F := F) width repetitions)
    have totalPositive : (0 : Rat) < total := by
      exact_mod_cast Fintype.card_pos
    calc
      affineBatchFailureProbability system linearMaskSum =
          (affineBatchFailureSet system linearMaskSum).card / total := rfl
      _ ≤
          (uniformAffineMatrixFailureSet
            (linearResidual system)
            (fun repetition => -linearMaskSum repetition)).card / total := by
        apply (div_le_div_iff_of_pos_right totalPositive).2
        exact_mod_cast Finset.card_le_card
          (linear_failure_affine_event_subset
            system linearMaskSum linear failure)
      _ = uniformAffineMatrixFailureProbability
          (linearResidual system)
          (fun repetition => -linearMaskSum repetition) := rfl
      _ = ((1 : Rat) / Fintype.card F) ^ repetitions :=
        uniform_affine_matrix_failure_probability_exact residualNonzero _
  · push Not at nonlinearSatisfied
    obtain ⟨nonlinear, node, nodeMembership, failure⟩ := nonlinearSatisfied
    have residualNonzero :
        ∃ coordinate, nonlinearResidual system node coordinate ≠ 0 :=
      ⟨nonlinear, failure⟩
    let total :=
      Fintype.card (CoefficientMatrix (F := F) width repetitions)
    have totalPositive : (0 : Rat) < total := by
      exact_mod_cast Fintype.card_pos
    calc
      affineBatchFailureProbability system linearMaskSum =
          (affineBatchFailureSet system linearMaskSum).card / total := rfl
      _ ≤
          (uniformMatrixFailureSet
            (nonlinearResidual system node) repetitions).card / total := by
        apply (div_le_div_iff_of_pos_right totalPositive).2
        exact_mod_cast Finset.card_le_card
          (nonlinear_failure_affine_event_subset
            system linearMaskSum nonlinear node nodeMembership failure)
      _ = uniformMatrixFailureProbability
          (nonlinearResidual system node) repetitions := rfl
      _ = independentUniformMatrixFailureProbability
          (nonlinearResidual system node) repetitions :=
        uniform_matrix_failure_probability_eq_independent _ _
      _ = ((1 : Rat) / Fintype.card F) ^ repetitions :=
        independent_uniform_matrix_failure_probability_exact
          residualNonzero repetitions

/--
Active Goldilocks instantiation of the second SmallWood term: one unsatisfied padded production
system survives all five uniform PIOP batching rows with probability at most `|F|^-5`.
-/
theorem active_unsatisfied_batch_failure_probability_le
    (system :
      System (F := Goldilocks) (Node := Node)
        (Nonlinear := Fin HegemonCrypto.SmallWoodTranscript.activePiopRowWidth)
        (Linear := Fin HegemonCrypto.SmallWoodTranscript.activePiopRowWidth))
    (unsatisfied : ¬ FullySatisfied system) :
    batchFailureProbability
        (repetitions := HegemonCrypto.SmallWoodTranscript.activePiopRepetitions) system ≤
      (epsilon2Numerator : Rat) / epsilon2Denominator := by
  calc
    batchFailureProbability
        (repetitions := HegemonCrypto.SmallWoodTranscript.activePiopRepetitions) system ≤
        ((1 : Rat) / Fintype.card Goldilocks) ^
          HegemonCrypto.SmallWoodTranscript.activePiopRepetitions :=
      unsatisfied_batch_failure_probability_le system unsatisfied
    _ = (epsilon2Numerator : Rat) / epsilon2Denominator := by
      rw [active_epsilon2_is_uniform_matrix_bound]
      simp [Goldilocks, ZMod.card, goldilocksOrder,
        Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus,
        HegemonCrypto.SmallWoodTranscript.activePiopRepetitions,
        activeProfile]

/--
Active Goldilocks affine instantiation. Every vector of linear-mask sums fixed before the five
uniform challenge rows has the same exact second-term bound.
-/
theorem active_unsatisfied_affine_batch_failure_probability_le
    (system :
      System (F := Goldilocks) (Node := Node)
        (Nonlinear := Fin HegemonCrypto.SmallWoodTranscript.activePiopRowWidth)
        (Linear := Fin HegemonCrypto.SmallWoodTranscript.activePiopRowWidth))
    (linearMaskSum :
      Fin HegemonCrypto.SmallWoodTranscript.activePiopRepetitions -> Goldilocks)
    (unsatisfied : ¬ FullySatisfied system) :
    affineBatchFailureProbability system linearMaskSum ≤
      (epsilon2Numerator : Rat) / epsilon2Denominator := by
  calc
    affineBatchFailureProbability system linearMaskSum ≤
        ((1 : Rat) / Fintype.card Goldilocks) ^
          HegemonCrypto.SmallWoodTranscript.activePiopRepetitions :=
      unsatisfied_affine_batch_failure_probability_le
        system linearMaskSum unsatisfied
    _ = (epsilon2Numerator : Rat) / epsilon2Denominator := by
      rw [active_epsilon2_is_uniform_matrix_bound]
      simp [Goldilocks, ZMod.card, goldilocksOrder,
        Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus,
        HegemonCrypto.SmallWoodTranscript.activePiopRepetitions,
        activeProfile]

section ProductionAdapter

/-- Embed one real nonlinear coordinate in the shared zero-padded production row. -/
def paddedNonlinearIndex
    (statement : Statement)
    (constraint : Fin statement.nonlinearConstraintCount) :
    Fin
      (HegemonCrypto.SmallWoodTranscript.productionPiopRowWidth
        statement.nonlinearConstraintCount statement.linearConstraintCount) :=
  ⟨constraint.val,
    constraint.isLt.trans_le
      (Nat.le_max_left
        statement.nonlinearConstraintCount statement.linearConstraintCount)⟩

/-- Embed one real sparse-linear coordinate in the shared zero-padded production row. -/
def paddedLinearIndex
    (statement : Statement)
    (constraint : Fin statement.linearConstraintCount) :
    Fin
      (HegemonCrypto.SmallWoodTranscript.productionPiopRowWidth
        statement.nonlinearConstraintCount statement.linearConstraintCount) :=
  ⟨constraint.val,
    constraint.isLt.trans_le
      (Nat.le_max_right
        statement.nonlinearConstraintCount statement.linearConstraintCount)⟩

/-- Removing a zero suffix from a finite sum preserves exactly the real production coordinates. -/
theorem sum_padded_fin
    {M : Type*}
    [AddCommMonoid M]
    {count width : Nat}
    (countLeWidth : count ≤ width)
    (term : Fin count -> M) :
    (∑ index : Fin width,
      if indexBound : index.val < count then
        term ⟨index.val, indexBound⟩
      else
        0) =
      ∑ index : Fin count, term index := by
  let padded : Nat -> M := fun index =>
    if indexBound : index < count then term ⟨index, indexBound⟩ else 0
  change (∑ index : Fin width, padded index.val) = _
  rw [Fin.sum_univ_eq_sum_range padded width]
  have widthEquation : width = count + (width - count) := by
    omega
  rw [widthEquation, Finset.sum_range_add]
  have tailZero :
      (∑ index ∈ Finset.range (width - count), padded (count + index)) = 0 := by
    apply Finset.sum_eq_zero
    intro index _
    simp [padded]
  rw [tailZero, add_zero, ← Fin.sum_univ_eq_sum_range padded count]
  apply Finset.sum_congr rfl
  intro index _
  simp [padded]

/--
Exact statement-specific PIOP system.  Rust draws one row at the larger constraint-family width;
the shorter family is represented here by zero polynomials and zero targets in the unused suffix.
-/
noncomputable def paddedProductionSystem
    {statement : Statement}
    {witness : Witness}
    {encoding : ProductionFieldEncoding (F := F)}
    (oracles : ProductionOracleRefinement statement witness encoding) :
    System (F := F) (Node := Nat)
      (Nonlinear := Fin
        (HegemonCrypto.SmallWoodTranscript.productionPiopRowWidth
          statement.nonlinearConstraintCount statement.linearConstraintCount))
      (Linear := Fin
        (HegemonCrypto.SmallWoodTranscript.productionPiopRowWidth
          statement.nonlinearConstraintCount statement.linearConstraintCount)) where
  nodes := Finset.range statement.lppcPackingFactor
  point := oracles.point
  pointInjective := oracles.pointInjective
  nonlinearIndices := Finset.univ
  nonlinearPolynomial := fun index =>
    if _indexBound : index.val < statement.nonlinearConstraintCount then
      oracles.nonlinearPolynomial index.val
    else
      0
  linearIndices := Finset.univ
  linearPolynomial := fun index =>
    if _indexBound : index.val < statement.linearConstraintCount then
      oracles.linearPolynomial index.val
    else
      0
  linearTarget := fun index =>
    if _indexBound : index.val < statement.linearConstraintCount then
      encoding.encode
        (toGoldilocks (fieldValue (statement.linearTargets.getD index.val 0)))
    else
      0

omit [Fintype F] [DecidableEq F] in
/-- Zero-padding does not change one nonlinear production batch. -/
theorem padded_production_nonlinear_batch_eq
    {statement : Statement}
    {witness : Witness}
    {encoding : ProductionFieldEncoding (F := F)}
    (oracles : ProductionOracleRefinement statement witness encoding)
    (coefficients :
      Fin
        (HegemonCrypto.SmallWoodTranscript.productionPiopRowWidth
          statement.nonlinearConstraintCount statement.linearConstraintCount) -> F) :
    nonlinearBatch (paddedProductionSystem oracles) coefficients =
      ∑ constraint : Fin statement.nonlinearConstraintCount,
        C (coefficients (paddedNonlinearIndex statement constraint)) *
          oracles.nonlinearPolynomial constraint.val := by
  convert sum_padded_fin
      (M := F[X])
      (Nat.le_max_left
        statement.nonlinearConstraintCount statement.linearConstraintCount)
      (fun constraint : Fin statement.nonlinearConstraintCount =>
        C (coefficients (paddedNonlinearIndex statement constraint)) *
          oracles.nonlinearPolynomial constraint.val) using 1
  all_goals
    simp [nonlinearBatch, batch, paddedProductionSystem, paddedNonlinearIndex]
  all_goals rfl

omit [Fintype F] [DecidableEq F] in
/-- Zero-padding does not change one sparse-linear production batch. -/
theorem padded_production_linear_batch_eq
    {statement : Statement}
    {witness : Witness}
    {encoding : ProductionFieldEncoding (F := F)}
    (oracles : ProductionOracleRefinement statement witness encoding)
    (coefficients :
      Fin
        (HegemonCrypto.SmallWoodTranscript.productionPiopRowWidth
          statement.nonlinearConstraintCount statement.linearConstraintCount) -> F) :
    linearBatch (paddedProductionSystem oracles) coefficients =
      ∑ constraint : Fin statement.linearConstraintCount,
        C (coefficients (paddedLinearIndex statement constraint)) *
          oracles.linearPolynomial constraint.val := by
  convert sum_padded_fin
      (M := F[X])
      (Nat.le_max_right
        statement.nonlinearConstraintCount statement.linearConstraintCount)
      (fun constraint : Fin statement.linearConstraintCount =>
        C (coefficients (paddedLinearIndex statement constraint)) *
          oracles.linearPolynomial constraint.val) using 1
  all_goals
    simp [linearBatch, batch, paddedProductionSystem, paddedLinearIndex]
  all_goals rfl

omit [Fintype F] [DecidableEq F] in
/-- Zero-padding does not change the challenge-weighted sparse-linear public target. -/
theorem padded_production_linear_target_batch_eq
    {statement : Statement}
    {witness : Witness}
    {encoding : ProductionFieldEncoding (F := F)}
    (oracles : ProductionOracleRefinement statement witness encoding)
    (coefficients :
      Fin
        (HegemonCrypto.SmallWoodTranscript.productionPiopRowWidth
          statement.nonlinearConstraintCount statement.linearConstraintCount) -> F) :
    Finset.univ.sum (fun linear =>
        coefficients linear *
          (paddedProductionSystem oracles).linearTarget linear) =
      ∑ constraint : Fin statement.linearConstraintCount,
        coefficients (paddedLinearIndex statement constraint) *
          encoding.encode
            (toGoldilocks
              (fieldValue (statement.linearTargets.getD constraint.val 0))) := by
  convert sum_padded_fin
      (M := F)
      (Nat.le_max_right
        statement.nonlinearConstraintCount statement.linearConstraintCount)
      (fun constraint : Fin statement.linearConstraintCount =>
        coefficients (paddedLinearIndex statement constraint) *
          encoding.encode
            (toGoldilocks
              (fieldValue (statement.linearTargets.getD constraint.val 0)))) using 1
  all_goals simp [paddedProductionSystem, paddedLinearIndex]
  all_goals rfl

omit [Fintype F] [DecidableEq F] in
/-- Removing the zero padding recovers the exact production-oracle satisfaction predicate. -/
theorem padded_production_fully_satisfied_implies_system_satisfied
    {statement : Statement}
    {witness : Witness}
    {encoding : ProductionFieldEncoding (F := F)}
    (oracles : ProductionOracleRefinement statement witness encoding)
    (satisfied : FullySatisfied (paddedProductionSystem oracles)) :
    oracles.system.Satisfied := by
  constructor
  · intro constraint constraintMembership node nodeMembership
    have constraintBound : constraint < statement.nonlinearConstraintCount :=
      List.mem_range.mp constraintMembership
    let paddedIndex :
        Fin (HegemonCrypto.SmallWoodTranscript.productionPiopRowWidth
          statement.nonlinearConstraintCount statement.linearConstraintCount) :=
      ⟨constraint, constraintBound.trans_le
        (Nat.le_max_left _ _)⟩
    have paddedEquation :=
      satisfied.1 paddedIndex node nodeMembership
    simpa [paddedProductionSystem, paddedIndex, constraintBound,
      ProductionOracleRefinement.system] using paddedEquation
  · intro constraint constraintMembership
    have constraintBound : constraint < statement.linearConstraintCount :=
      List.mem_range.mp constraintMembership
    let paddedIndex :
        Fin (HegemonCrypto.SmallWoodTranscript.productionPiopRowWidth
          statement.nonlinearConstraintCount statement.linearConstraintCount) :=
      ⟨constraint, constraintBound.trans_le
        (Nat.le_max_right _ _)⟩
    have paddedEquation := satisfied.2 paddedIndex
    simpa [paddedProductionSystem, paddedIndex, constraintBound,
      ProductionOracleRefinement.system] using paddedEquation

omit [Fintype F] [DecidableEq F] in
/-- Every exact production-oracle solution also satisfies the zero-padded dynamic PIOP system. -/
theorem system_satisfied_implies_padded_production_fully_satisfied
    {statement : Statement}
    {witness : Witness}
    {encoding : ProductionFieldEncoding (F := F)}
    (oracles : ProductionOracleRefinement statement witness encoding)
    (satisfied : oracles.system.Satisfied) :
    FullySatisfied (paddedProductionSystem oracles) := by
  constructor
  · intro nonlinear node nodeMembership
    by_cases nonlinearBound :
        nonlinear.val < statement.nonlinearConstraintCount
    · have originalEquation :=
        satisfied.1 nonlinear.val (List.mem_range.mpr nonlinearBound)
          node nodeMembership
      simpa [paddedProductionSystem, nonlinearBound,
        ProductionOracleRefinement.system] using originalEquation
    · simp [paddedProductionSystem, nonlinearBound]
  · intro linear
    by_cases linearBound : linear.val < statement.linearConstraintCount
    · have originalEquation :=
        satisfied.2 linear.val (List.mem_range.mpr linearBound)
      simpa [paddedProductionSystem, linearBound,
        ProductionOracleRefinement.system] using originalEquation
    · simp [paddedProductionSystem, linearBound, nodeSum]

omit [Fintype F] [DecidableEq F] in
theorem padded_production_fully_satisfied_iff
    {statement : Statement}
    {witness : Witness}
    {encoding : ProductionFieldEncoding (F := F)}
    (oracles : ProductionOracleRefinement statement witness encoding) :
    FullySatisfied (paddedProductionSystem oracles) ↔
      oracles.system.Satisfied :=
  ⟨padded_production_fully_satisfied_implies_system_satisfied oracles,
    system_satisfied_implies_padded_production_fully_satisfied oracles⟩

/--
Exact dynamic production batching bound.  It applies to every activity mask and does not assume
that all transactions use the fully populated 18,342-column maximum.
-/
theorem production_unsatisfied_batch_failure_probability_le
    {statement : Statement}
    {witness : Witness}
    {encoding : ProductionFieldEncoding (F := Goldilocks)}
    (oracles :
      ProductionOracleRefinement
        (F := Goldilocks) statement witness encoding)
    (unsatisfied : ¬ oracles.system.Satisfied) :
    batchFailureProbability
        (repetitions := HegemonCrypto.SmallWoodTranscript.activePiopRepetitions)
        (paddedProductionSystem oracles) ≤
      (epsilon2Numerator : Rat) / epsilon2Denominator := by
  have paddedUnsatisfied : ¬ FullySatisfied (paddedProductionSystem oracles) := by
    intro paddedSatisfied
    exact unsatisfied
      (padded_production_fully_satisfied_implies_system_satisfied
        oracles paddedSatisfied)
  calc
    batchFailureProbability
        (repetitions := HegemonCrypto.SmallWoodTranscript.activePiopRepetitions)
        (paddedProductionSystem oracles) ≤
        ((1 : Rat) / Fintype.card Goldilocks) ^
          HegemonCrypto.SmallWoodTranscript.activePiopRepetitions :=
      unsatisfied_batch_failure_probability_le
        (paddedProductionSystem oracles) paddedUnsatisfied
    _ = (epsilon2Numerator : Rat) / epsilon2Denominator := by
      rw [active_epsilon2_is_uniform_matrix_bound]
      simp [Goldilocks, ZMod.card, goldilocksOrder,
        Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus,
        HegemonCrypto.SmallWoodTranscript.activePiopRepetitions,
        activeProfile]

end ProductionAdapter

end FiniteProbability

end

end HegemonCrypto.SmallWood.PiopExtraction
