import HegemonCrypto.SmallWoodV8Smz9SampledAcceptance

/-!
# Fixed-prefix SMZ9 candidate mismatch at accepted queries

The source's 140 data words and five masks, and each candidate's 140 data and five mask
polynomials, are fixed before the uniform matrix. The response may depend on the entire matrix.
The final exact twenty-subset is independent of that matrix. We count outcomes where the response
equals the candidate's combined polynomial, every queried equation accepts, and at least one
queried source position differs from the candidate.

For each fixed query set, one mismatching position can be chosen without looking at the matrix.
Its fixed nonzero affine residual costs at most `p^-5`; a mask-only mismatch is impossible.
Thus the single-candidate loss is `p^-5`, stronger than the direct twenty-position union bound.
A finite prefix-fixed family loses only its cardinality. No existence/coverage of such a family,
degree test, exact-relation witness, commitment extraction, Fiat--Shamir/QROM transfer, or
production security is supplied here.
-/

namespace HegemonCrypto.SmallWood.V8Smz9RobustQueryMismatch

open Polynomial
open scoped BigOperators
open HegemonCrypto.SmallWoodPowerBatching

noncomputable section

set_option maxHeartbeats 100000
set_option maxRecDepth 5000

namespace FiniteEvents

variable {Outcome Index Prefix : Type*}
variable [Fintype Outcome]

def probability (event : Finset Outcome) : Rat := event.card / Fintype.card Outcome

theorem probability_mono {left right : Finset Outcome} (subset : left ⊆ right) :
    probability left ≤ probability right := by
  apply div_le_div_of_nonneg_right _ (Nat.cast_nonneg _)
  exact_mod_cast Finset.card_le_card subset

theorem probability_empty : probability (∅ : Finset Outcome) = 0 := by
  simp only [probability, Finset.card_empty, Nat.cast_zero, zero_div]

variable [DecidableEq Outcome]

theorem union_probability_le [DecidableEq Index] (indices : Finset Index)
    (events : Index → Finset Outcome) (bound : Rat)
    (bounded : ∀ index ∈ indices, probability (events index) ≤ bound) :
    probability (indices.biUnion events) ≤ indices.card * bound := by
  calc
    probability (indices.biUnion events) ≤
        (∑ index ∈ indices, (events index).card : Nat) / Fintype.card Outcome := by
      apply div_le_div_of_nonneg_right _ (Nat.cast_nonneg _)
      exact_mod_cast Finset.card_biUnion_le
    _ = ∑ index ∈ indices, probability (events index) := by
      simp only [probability, Nat.cast_sum, Finset.sum_div]
    _ ≤ ∑ _index ∈ indices, bound := Finset.sum_le_sum bounded
    _ = indices.card * bound := by simp only [Finset.sum_const, nsmul_eq_mul]

variable [Fintype Prefix]

/-- Accepted outcomes in the independent prefix/outcome product experiment. -/
abbrev Accepted (events : Prefix → Finset Outcome) :=
  (context : Prefix) × { outcome // outcome ∈ events context }

def jointProbability (events : Prefix → Finset Outcome) : Rat :=
  Fintype.card (Accepted events) / (Fintype.card Prefix * Fintype.card Outcome)

omit [DecidableEq Outcome] in
theorem joint_probability_eq_average (events : Prefix → Finset Outcome) :
    jointProbability events =
      (∑ context, probability (events context)) / Fintype.card Prefix := by
  unfold jointProbability probability
  rw [Fintype.card_sigma]
  simp only [Fintype.card_coe, Nat.cast_sum]
  rw [← Finset.sum_div, div_div, mul_comm]

omit [DecidableEq Outcome] in
theorem joint_probability_le [Nonempty Prefix] (events : Prefix → Finset Outcome) (bound : Rat)
    (bounded : ∀ context, probability (events context) ≤ bound) :
    jointProbability events ≤ bound := by
  rw [joint_probability_eq_average]
  have prefixPositive : (0 : Rat) < Fintype.card Prefix := by
    exact_mod_cast Fintype.card_pos (α := Prefix)
  apply (div_le_iff₀ prefixPositive).mpr
  calc
    (∑ context, probability (events context)) ≤ ∑ _context : Prefix, bound :=
      Finset.sum_le_sum fun context _ => bounded context
    _ = bound * Fintype.card Prefix := by
      simp only [Finset.sum_const, Finset.card_univ, nsmul_eq_mul, mul_comm]

end FiniteEvents

abbrev Matrix := V8Smz9AccumulatedExtraction.Smz9Matrix
abbrev DataRow := Fin V8Smz9LogicalOracle.decsRowCount
abbrev MaskRow := Fin V8Smz9LogicalOracle.decsEta
abbrev Position := Fin V8Smz9LogicalOracle.decsDomainSize
abbrev Challenge := V8Smz9LogicalOracle.DecsOpeningChallenge
abbrev Response := Matrix → MaskRow → Goldilocks[X]

/-- All source values are theorem arguments, never functions of the matrix or final subset. -/
structure Source where
  data : DataRow → Position → Goldilocks
  masks : MaskRow → Position → Goldilocks

/-- A polynomial candidate is not, by this structure alone, a valid transaction witness. -/
structure Candidate where
  data : DataRow → Goldilocks[X]
  masks : MaskRow → Goldilocks[X]

abbrev point (position : Position) : Goldilocks :=
  V8Smz9DisjointCoset.evaluationPoint position

def combined (candidate : Candidate) (matrix : Matrix) (row : MaskRow) : Goldilocks[X] :=
  (∑ column, C (matrix row column) * candidate.data column) + candidate.masks row

def sourceCombination (source : Source) (matrix : Matrix) (row : MaskRow)
    (position : Position) : Goldilocks :=
  (∑ column, matrix row column * source.data column position) + source.masks row position

def dataResidual (source : Source) (candidate : Candidate) (position : Position)
    (column : DataRow) : Goldilocks :=
  source.data column position - (candidate.data column).eval (point position)

def maskTarget (source : Source) (candidate : Candidate) (position : Position)
    (row : MaskRow) : Goldilocks :=
  (candidate.masks row).eval (point position) - source.masks row position

def Mismatch (source : Source) (candidate : Candidate) (position : Position) : Prop :=
  (∃ column, source.data column position ≠ (candidate.data column).eval (point position)) ∨
    (∃ row, source.masks row position ≠ (candidate.masks row).eval (point position))

def QueryAccepts (source : Source) (response : Response) (matrix : Matrix)
    (challenge : Challenge) : Prop :=
  ∀ position ∈ challenge.val, ∀ row,
    sourceCombination source matrix row position = (response matrix row).eval (point position)

def ResponseConsistent (candidate : Candidate) (response : Response) (matrix : Matrix) : Prop :=
  ∀ row, response matrix row = combined candidate matrix row

/-- The actual event: polynomial response equality, all queried equations, and a queried mismatch. -/
def robustMismatchEvent (source : Source) (candidate : Candidate) (response : Response)
    (challenge : Challenge) : Finset Matrix := by
  classical
  exact Finset.univ.filter fun matrix =>
    ResponseConsistent candidate response matrix ∧
    QueryAccepts source response matrix challenge ∧
    ∃ position ∈ challenge.val, Mismatch source candidate position

def pointMismatchEvent (source : Source) (candidate : Candidate)
    (position : Position) : Finset Matrix := by
  classical
  exact Finset.univ.filter fun matrix => Mismatch source candidate position ∧
    ∀ row, uniformDotProduct (dataResidual source candidate position) (matrix row) =
      maskTarget source candidate position row

theorem mem_robust_mismatch_event (source : Source) (candidate : Candidate) (response : Response)
    (challenge : Challenge) (matrix : Matrix) :
    matrix ∈ robustMismatchEvent source candidate response challenge ↔
      ResponseConsistent candidate response matrix ∧
      QueryAccepts source response matrix challenge ∧
      ∃ position ∈ challenge.val, Mismatch source candidate position := by
  simp only [robustMismatchEvent, Finset.mem_filter, Finset.mem_univ, true_and]

theorem mem_point_mismatch_event (source : Source) (candidate : Candidate)
    (position : Position) (matrix : Matrix) :
    matrix ∈ pointMismatchEvent source candidate position ↔
      Mismatch source candidate position ∧
      ∀ row, uniformDotProduct (dataResidual source candidate position) (matrix row) =
        maskTarget source candidate position row := by
  simp only [pointMismatchEvent, Finset.mem_filter, Finset.mem_univ, true_and]

theorem source_equation_implies_affine (source : Source) (candidate : Candidate)
    (matrix : Matrix) (position : Position) (row : MaskRow)
    (equation : sourceCombination source matrix row position =
      (combined candidate matrix row).eval (point position)) :
    uniformDotProduct (dataResidual source candidate position) (matrix row) =
      maskTarget source candidate position row := by
  have evaluated : (combined candidate matrix row).eval (point position) =
      (∑ column, matrix row column * (candidate.data column).eval (point position)) +
        (candidate.masks row).eval (point position) := by
    simp [combined, eval_finsetSum]
  rw [evaluated] at equation
  unfold sourceCombination at equation
  simp only [uniformDotProduct, dataResidual, sub_mul, Finset.sum_sub_distrib,
    maskTarget]
  simp_rw [mul_comm (source.data _ position),
    mul_comm ((candidate.data _).eval (point position))]
  linear_combination equation

private theorem mem_affine_event {F : Type*} [Field F] [Fintype F] [DecidableEq F]
    {width repetitions : Nat} (residual : Fin width → F) (target : Fin repetitions → F)
    (matrix : CoefficientMatrix (F := F) width repetitions) :
    matrix ∈ uniformAffineMatrixFailureSet residual target ↔
      ∀ row, uniformDotProduct residual (matrix row) = target row := by
  simp only [uniformAffineMatrixFailureSet, Fintype.mem_piFinset,
    uniformDotFiberSet, Finset.mem_filter, Finset.mem_univ, true_and]

-- The naming-only linter unfolds the concrete matrix enumeration; kernel checking is unchanged.
set_option linter.constructorNameAsVariable false in
/-- A mismatching fixed position has at most one nonzero affine fiber's probability. -/
theorem point_mismatch_probability_le (source : Source) (candidate : Candidate)
    (position : Position) :
    FiniteEvents.probability (pointMismatchEvent source candidate position) ≤
      ((1 : Rat) / Fintype.card Goldilocks) ^ 5 := by
  classical
  by_cases nonzero : ∃ column, dataResidual source candidate position column ≠ 0
  · have subset : pointMismatchEvent source candidate position ⊆
        uniformAffineMatrixFailureSet (dataResidual source candidate position)
          (maskTarget source candidate position) := by
      intro matrix member
      rw [mem_point_mismatch_event] at member
      rw [mem_affine_event]
      exact member.2
    apply (FiniteEvents.probability_mono subset).trans
    exact (uniform_affine_matrix_failure_probability_exact nonzero
      (maskTarget source candidate position)).le
  · have residualZero : ∀ column, dataResidual source candidate position column = 0 := by
      simpa only [not_exists, not_not] using nonzero
    have empty : pointMismatchEvent source candidate position = ∅ := by
      apply Finset.eq_empty_iff_forall_notMem.mpr
      intro matrix member
      rw [mem_point_mismatch_event] at member
      have info := member
      rcases info.1 with dataMismatch | maskMismatch
      · obtain ⟨column, different⟩ := dataMismatch
        exact different (sub_eq_zero.mp (residualZero column))
      · obtain ⟨row, different⟩ := maskMismatch
        have impossible := info.2 row
        simp only [uniformDotProduct, residualZero, zero_mul, Finset.sum_const_zero] at impossible
        exact different (sub_eq_zero.mp impossible.symm).symm
    rw [empty, FiniteEvents.probability_empty]
    positivity

set_option linter.constructorNameAsVariable false in
/-- For fixed queries, choose one mismatch independently of the matrix; no twenty-fold union. -/
theorem fixed_query_mismatch_probability_le (source : Source) (candidate : Candidate)
    (response : Response) (challenge : Challenge) :
    FiniteEvents.probability (robustMismatchEvent source candidate response challenge) ≤
      ((1 : Rat) / Fintype.card Goldilocks) ^ 5 := by
  classical
  by_cases hitsMismatch : ∃ position ∈ challenge.val, Mismatch source candidate position
  · obtain ⟨position, queried, different⟩ := hitsMismatch
    have subset : robustMismatchEvent source candidate response challenge ⊆
        pointMismatchEvent source candidate position := by
      intro matrix member
      rw [mem_robust_mismatch_event] at member
      have info := member
      rw [mem_point_mismatch_event]
      refine ⟨different, ?_⟩
      intro row
      apply source_equation_implies_affine source candidate matrix position row
      rw [← info.1 row]
      exact info.2.1 position queried row
    exact (FiniteEvents.probability_mono subset).trans
      (point_mismatch_probability_le source candidate position)
  · have empty : robustMismatchEvent source candidate response challenge = ∅ := by
      apply Finset.eq_empty_iff_forall_notMem.mpr
      intro matrix member
      rw [mem_robust_mismatch_event] at member
      exact hitsMismatch member.2.2
    rw [empty, FiniteEvents.probability_empty]
    positivity

/-- Exact accepted fraction in the independent matrix/exact-twenty-subset experiment. -/
def jointMismatchProbability (source : Source) (candidate : Candidate) (response : Response) : Rat :=
  FiniteEvents.jointProbability (robustMismatchEvent source candidate response)

theorem joint_mismatch_probability_le (source : Source) (candidate : Candidate)
    (response : Response) :
    jointMismatchProbability source candidate response ≤
      ((1 : Rat) / Fintype.card Goldilocks) ^ 5 := by
  exact FiniteEvents.joint_probability_le _ _
    (fixed_query_mismatch_probability_le source candidate response)

section FixedFamily

variable {Label : Type*} [Fintype Label] [DecidableEq Label]

/-- The entire candidate family is fixed before the matrix; membership may be selected afterward. -/
def familyMismatchEvent (source : Source) (candidates : Label → Candidate) (response : Response)
    (challenge : Challenge) : Finset Matrix :=
  Finset.univ.biUnion fun label => robustMismatchEvent source (candidates label) response challenge

def familyMismatchProbability (source : Source) (candidates : Label → Candidate)
    (response : Response) : Rat :=
  FiniteEvents.jointProbability (familyMismatchEvent source candidates response)

theorem fixed_family_mismatch_probability_le (source : Source) (candidates : Label → Candidate)
    (response : Response) :
    familyMismatchProbability source candidates response ≤
      Fintype.card Label * (((1 : Rat) / Fintype.card Goldilocks) ^ 5) := by
  apply FiniteEvents.joint_probability_le
  intro challenge
  have bound := FiniteEvents.union_probability_le (Finset.univ : Finset Label)
    (fun label => robustMismatchEvent source (candidates label) response challenge)
    (((1 : Rat) / Fintype.card Goldilocks) ^ 5)
    (fun label _ => fixed_query_mismatch_probability_le source (candidates label) response challenge)
  simpa only [familyMismatchEvent, Finset.card_univ] using bound

end FixedFamily

end

end HegemonCrypto.SmallWood.V8Smz9RobustQueryMismatch
