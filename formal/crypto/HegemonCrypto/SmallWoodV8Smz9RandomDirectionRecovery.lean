import HegemonCrypto.SmallWoodV8Smz9McaSourceBinding

/-!
# One random direction for arbitrary-source recovery

The auxiliary direction is a proof-only independent variable. It does not
change the verifier, source, response, challenge distribution or extractor.
The first counting lemma detects a non-codeword data column without a union
bound over the number of columns.
-/

namespace HegemonCrypto.SmallWood.V8Smz9RandomDirectionRecovery

open Polynomial V8Smz9McaRecovery
open scoped BigOperators

noncomputable section

set_option maxRecDepth 5000
set_option backward.isDefEq.respectTransparency false

variable {F Index Position Row : Type*} [Field F] [Fintype Index] [DecidableEq Index]

def directionWord (data : Index → Position → F) (direction : Index → F) : Position → F :=
  fun index => ∑ column, direction column * data column index

theorem direction_word_update (data : Index → Position → F) (direction : Index → F)
    (column : Index) (left right : F) (index : Position) :
    directionWord data (Function.update direction column left) index -
        directionWord data (Function.update direction column right) index =
      (left - right) * data column index := by
  classical
  unfold directionWord
  rw [← Finset.sum_sub_distrib, Finset.sum_eq_single column]
  · simp only [Function.update_self]
    ring
  · intro other _ different
    simp only [Function.update_of_ne different, sub_self]
  · simp

theorem code_on_smul (point : Position → F) (degree : ℕ) (word : Position → F)
    (support : Finset Position) (scalar : F) (coded : CodeOn point degree word support) :
    CodeOn point degree (fun index => scalar * word index) support := by
  obtain ⟨polynomial, bounded, agrees⟩ := coded
  refine ⟨C scalar * polynomial, (natDegree_C_mul_le _ _).trans bounded, ?_⟩
  intro index member
  simp only [eval_mul, eval_C, agrees index member]

/-- On a fiber in a non-codeword column, at most one scalar makes the
random combination a codeword on the fixed support. -/
theorem coded_direction_fiber_unique (point : Position → F) (degree : ℕ)
    (data : Index → Position → F) (support : Finset Position)
    (column : Index) (notCoded : ¬ CodeOn point degree (data column) support)
    (direction : Index → F) (left right : F)
    (leftCode : CodeOn point degree (directionWord data (Function.update direction column left)) support)
    (rightCode : CodeOn point degree (directionWord data (Function.update direction column right)) support) :
    left = right := by
  by_contra different
  have differenceCode := code_on_sub_smul point degree
    (directionWord data (Function.update direction column left))
    (directionWord data (Function.update direction column right)) support 1 leftCode rightCode
  have scaledCode : CodeOn point degree (fun index => (left - right) * data column index)
      support := by
    simpa only [one_mul, direction_word_update] using differenceCode
  have recovered := code_on_smul point degree _ support (left - right)⁻¹ scaledCode
  apply notCoded
  have nonzero : left - right ≠ 0 := sub_ne_zero.mpr different
  simpa only [← mul_assoc, inv_mul_cancel₀ nonzero, one_mul] using recovered

section DirectionCounting

variable [Fintype F]

def codedDirectionIndicator (point : Position → F) (degree : ℕ)
    (data : Index → Position → F) (support : Finset Position) (direction : Index → F) : ℕ := by
  classical
  exact if CodeOn point degree (directionWord data direction) support then 1 else 0

theorem coded_direction_fiber_sum_le_one (point : Position → F) (degree : ℕ)
    (data : Index → Position → F) (support : Finset Position)
    (column : Index) (notCoded : ¬ CodeOn point degree (data column) support)
    (direction : Index → F) :
    (∑ scalar : F, codedDirectionIndicator point degree data support
      (Function.update direction column scalar)) ≤ 1 := by
  classical
  let good := Finset.univ.filter fun scalar : F =>
    CodeOn point degree (directionWord data (Function.update direction column scalar)) support
  have small : good.card ≤ 1 := by
    apply Finset.card_le_one.mpr
    intro left leftMem right rightMem
    exact coded_direction_fiber_unique point degree data support column notCoded direction
      left right (Finset.mem_filter.mp leftMem).2 (Finset.mem_filter.mp rightMem).2
  simpa only [good, Finset.card_filter, codedDirectionIndicator] using small

/-- A nonzero quotient is missed by at most a 1/|F| fraction of all auxiliary
directions. The zero direction is included and correctly counted as a miss. -/
theorem coded_direction_sum_bound (point : Position → F) (degree : ℕ)
    (data : Index → Position → F) (support : Finset Position)
    (column : Index) (notCoded : ¬ CodeOn point degree (data column) support) :
    (∑ direction : Index → F, codedDirectionIndicator point degree data support direction) *
        Fintype.card F ≤ Fintype.card (Index → F) := by
  have bound := coordinate_sum_bound column
    (codedDirectionIndicator point degree data support) 1
    (coded_direction_fiber_sum_le_one point degree data support column notCoded)
  simpa only [Nat.mul_one] using bound

end DirectionCounting

def matrixShear (direction : Index → F) (pivot : Index)
    (base : Index → Row → F) : Index → Row → F := fun column row =>
  if column = pivot then base pivot row * direction pivot
  else base column row + base pivot row * direction column

def matrixUnshear (direction : Index → F) (pivot : Index)
    (matrix : Index → Row → F) : Index → Row → F := fun column row =>
  if column = pivot then matrix pivot row / direction pivot
  else matrix column row - (matrix pivot row / direction pivot) * direction column

def matrixShearEquiv (direction : Index → F) (pivot : Index)
    (nonzero : direction pivot ≠ 0) : (Index → Row → F) ≃ (Index → Row → F) where
  toFun := matrixShear direction pivot
  invFun := matrixUnshear direction pivot
  left_inv base := by
    funext column row
    by_cases same : column = pivot
    · subst column
      simp [matrixShear, matrixUnshear, nonzero]
    · simp [matrixShear, matrixUnshear, same, nonzero]
  right_inv matrix := by
    funext column row
    by_cases same : column = pivot
    · subst column
      simp [matrixShear, matrixUnshear, nonzero]
    · simp [matrixShear, matrixUnshear, same]

def sourceMixture (data : Index → Position → F) (masks : Row → Position → F)
    (matrix : Index → Row → F) : Row → Position → F :=
  fun row index => masks row index + ∑ column, matrix column row * data column index

omit [Fintype Index] in
theorem shear_update_coefficient (direction : Index → F) (pivot : Index)
    (base : Index → Row → F) (coefficient : Row → F) (column : Index) (row : Row) :
    matrixShear direction pivot (Function.update base pivot coefficient) column row =
      Function.update base pivot 0 column row + coefficient row * direction column := by
  classical
  by_cases same : column = pivot
  · subst column
    simp [matrixShear]
  · simp [matrixShear, same]

theorem shear_update_is_line (data : Index → Position → F) (masks : Row → Position → F)
    (direction : Index → F) (pivot : Index) (base : Index → Row → F)
    (coefficient : Row → F) :
    sourceMixture data masks (matrixShear direction pivot (Function.update base pivot coefficient)) =
      lineWord (sourceMixture data masks (Function.update base pivot 0))
        (directionWord data direction) coefficient := by
  funext row index
  simp only [sourceMixture, lineWord, directionWord, shear_update_coefficient, add_mul,
    Finset.sum_add_distrib, ← Finset.mul_sum, mul_assoc]
  ring

variable [Fintype F] [Fintype Position] [Fintype Row] [DecidableEq Row]

/-- The weight of a detected failure on the response's full support. -/
def detectedWeight (point : Position → F) (degree threshold queryCount : ℕ)
    (data : Index → Position → F) (masks : Row → Position → F)
    (response : (Index → Row → F) → BoundedResponse F Row degree)
    (direction : Index → F) (matrix : Index → Row → F) : ℕ := by
  classical
  let support := agreement point (sourceMixture data masks matrix)
    (responsePolynomials (response matrix))
  exact if threshold ≤ support.card ∧ ¬ CodeOn point degree (directionWord data direction) support
    then Nat.choose support.card queryCount else 0

/-- Any nonzero auxiliary direction exposes just one uniform five-coordinate
line. The adversarial response can still depend on the entire actual matrix. -/
theorem detected_weight_sum_bound (point : Position → F) (degree threshold queryCount : ℕ)
    (data : Index → Position → F) (masks : Row → Position → F)
    (response : (Index → Row → F) → BoundedResponse F Row degree)
    (direction : Index → F) (pivot : Index) (nonzero : direction pivot ≠ 0) :
    (∑ matrix : Index → Row → F,
      detectedWeight point degree threshold queryCount data masks response direction matrix) *
        Fintype.card (Row → F) ≤ Fintype.card (Index → Row → F) *
          universalLineBudget (Row := Row) point degree threshold queryCount := by
  classical
  let transform := matrixShearEquiv (Row := Row) direction pivot nonzero
  let cost := fun base => detectedWeight point degree threshold queryCount
    data masks response direction (transform base)
  have fiber (base : Index → Row → F) :
      (∑ coefficient : Row → F, cost (Function.update base pivot coefficient)) ≤
        universalLineBudget (Row := Row) point degree threshold queryCount := by
    let prior := sourceMixture data masks (Function.update base pivot 0)
    have each (coefficient : Row → F) :
        cost (Function.update base pivot coefficient) ≤
          badCoefficientWeight point degree threshold queryCount prior
            (directionWord data direction) coefficient := by
      have responseBound := bad_response_weight_le_coefficient_weight point degree threshold queryCount prior
        (directionWord data direction) coefficient
        (response (transform (Function.update base pivot coefficient)))
      change detectedWeight point degree threshold queryCount data masks response direction
        (matrixShear direction pivot (Function.update base pivot coefficient)) ≤ _
      unfold detectedWeight
      rw [shear_update_is_line]
      exact responseBound
    exact (Finset.sum_le_sum fun coefficient _ => each coefficient).trans (by
      have lineBound := line_budget_le_universal point degree threshold queryCount prior
        (directionWord data direction)
      unfold lineCoefficientBudget at lineBound
      convert lineBound using 1
      congr 1
      apply Finset.sum_congr
      · ext coefficient
        simp
      · intro coefficient _
        rfl)
  have total := coordinate_sum_bound pivot cost
    (universalLineBudget (Row := Row) point degree threshold queryCount) fiber
  have same : (∑ base, cost base) = ∑ matrix : Index → Row → F,
      detectedWeight point degree threshold queryCount data masks response direction matrix := by
    exact Fintype.sum_equiv transform cost
      (detectedWeight point degree threshold queryCount data masks response direction)
      (fun _ => rfl)
  rw [same] at total
  exact total

omit [Fintype F] [Fintype Row] [DecidableEq Row] [Fintype Position] in
def codeSpace (point : Position → F) (degree : ℕ) (support : Finset Position) :
    Submodule F (Position → F) where
  carrier := {word | CodeOn point degree word support}
  zero_mem' := by
    exact ⟨0, by simp, by simp⟩
  add_mem' := by
    intro left right leftCode rightCode
    obtain ⟨lp, ld, la⟩ := leftCode
    obtain ⟨rp, rd, ra⟩ := rightCode
    exact ⟨lp + rp, (natDegree_add_le _ _).trans (max_le ld rd), by
      intro index member
      simp only [eval_add, la index member, ra index member, Pi.add_apply]⟩
  smul_mem' := by
    intro scalar word coded
    exact code_on_smul point degree word support scalar coded

omit [Fintype F] [Fintype Row] [DecidableEq Row] [DecidableEq Index] [Fintype Position] in
theorem coded_data_and_mixture_imply_coded_masks (point : Position → F) (degree : ℕ)
    (data : Index → Position → F) (masks : Row → Position → F)
    (matrix : Index → Row → F) (support : Finset Position)
    (dataCode : ∀ column, CodeOn point degree (data column) support)
    (mixtureCode : VectorCodeOn point degree (sourceMixture data masks matrix) support) :
    VectorCodeOn point degree masks support := by
  intro row
  have sumCode : CodeOn point degree
      (fun index => ∑ column, matrix column row * data column index) support := by
    have sumMember : (∑ column, matrix column row • data column) ∈ codeSpace point degree support :=
      Submodule.sum_mem _ (fun column _ => Submodule.smul_mem _ _ (dataCode column))
    change CodeOn point degree (∑ column, matrix column row • data column) support at sumMember
    have sameWord : (∑ column, matrix column row • data column) =
        fun index => ∑ column, matrix column row * data column index := by
      funext index
      simp only [Finset.sum_apply, Pi.smul_apply, smul_eq_mul]
    rw [sameWord] at sumMember
    exact sumMember
  have recovered := code_on_sub_smul point degree (sourceMixture data masks matrix row)
    (fun index => ∑ column, matrix column row * data column index) support 1
    (mixtureCode row) sumCode
  simpa only [sourceMixture, one_mul, add_sub_cancel_right] using recovered

def sourceSupport (point : Position → F) (degree : ℕ)
    (data : Index → Position → F) (masks : Row → Position → F)
    (response : (Index → Row → F) → BoundedResponse F Row degree)
    (matrix : Index → Row → F) : Finset Position :=
  agreement point (sourceMixture data masks matrix) (responsePolynomials (response matrix))

/-- The calculated decoder's complete local recovery predicate. -/
def SourceRecovered (point : Position → F) (degree : ℕ)
    (data : Index → Position → F) (masks : Row → Position → F)
    (response : (Index → Row → F) → BoundedResponse F Row degree)
    (matrix : Index → Row → F) : Prop :=
  let support := sourceSupport point degree data masks response matrix
  degree < support.card ∧ VectorCodeOn point degree masks support ∧
    ∀ column, CodeOn point degree (data column) support

def largeFailureWeight (point : Position → F) (degree threshold queryCount : ℕ)
    (data : Index → Position → F) (masks : Row → Position → F)
    (response : (Index → Row → F) → BoundedResponse F Row degree)
    (matrix : Index → Row → F) : ℕ := by
  classical
  exact if threshold ≤ (sourceSupport point degree data masks response matrix).card ∧
      ¬ SourceRecovered point degree data masks response matrix
    then Nat.choose (sourceSupport point degree data masks response matrix).card queryCount else 0

omit [Fintype F] [Fintype Row] [DecidableEq Row] [DecidableEq Index] in
theorem large_unrecovered_has_noncoded_column (point : Position → F)
    (degree threshold : ℕ) (thresholdValid : degree < threshold)
    (data : Index → Position → F) (masks : Row → Position → F)
    (response : (Index → Row → F) → BoundedResponse F Row degree)
    (matrix : Index → Row → F)
    (large : threshold ≤ (sourceSupport point degree data masks response matrix).card)
    (failed : ¬ SourceRecovered point degree data masks response matrix) :
    ∃ column, ¬ CodeOn point degree (data column)
      (sourceSupport point degree data masks response matrix) := by
  classical
  by_contra allCoded
  push Not at allCoded
  apply failed
  refine ⟨thresholdValid.trans_le large, ?_, allCoded⟩
  apply coded_data_and_mixture_imply_coded_masks point degree data masks matrix _ allCoded
  intro row
  refine ⟨responsePolynomials (response matrix) row, bounded_response_degree _ row, ?_⟩
  intro index member
  exact (mem_agreement point _ _ index).mp member row

omit [Fintype Row] [DecidableEq Row] in
/-- Detection uses an independent direction only after fixing the entire actual
matrix and response. Thus the support in the 1/|F| counting lemma is fixed. -/
theorem large_failure_detected_weight_bound (point : Position → F)
    (degree threshold queryCount : ℕ) (thresholdValid : degree < threshold)
    (data : Index → Position → F) (masks : Row → Position → F)
    (response : (Index → Row → F) → BoundedResponse F Row degree)
    (matrix : Index → Row → F) :
    Fintype.card (Index → F) * (Fintype.card F - 1) *
        largeFailureWeight point degree threshold queryCount data masks response matrix ≤
      (∑ direction : Index → F,
        detectedWeight point degree threshold queryCount data masks response direction matrix) *
          Fintype.card F := by
  classical
  let support := sourceSupport point degree data masks response matrix
  change Fintype.card (Index → F) * (Fintype.card F - 1) *
    (if threshold ≤ support.card ∧ ¬ SourceRecovered point degree data masks response matrix
      then Nat.choose support.card queryCount else 0) ≤ _
  by_cases failure : threshold ≤ support.card ∧ ¬ SourceRecovered point degree data masks response matrix
  · obtain ⟨column, notCoded⟩ := large_unrecovered_has_noncoded_column point degree threshold
      thresholdValid data masks response matrix failure.1 failure.2
    have missed := coded_direction_sum_bound point degree data support column notCoded
    have partition :
        (∑ direction : Index → F,
          detectedWeight point degree threshold queryCount data masks response direction matrix) +
          (∑ direction : Index → F, codedDirectionIndicator point degree data support direction) *
            Nat.choose support.card queryCount =
        Fintype.card (Index → F) * Nat.choose support.card queryCount := by
      rw [Finset.sum_mul, ← Finset.sum_add_distrib]
      have term (direction : Index → F) :
          detectedWeight point degree threshold queryCount data masks response direction matrix +
              codedDirectionIndicator point degree data support direction *
                Nat.choose support.card queryCount = Nat.choose support.card queryCount := by
        unfold detectedWeight codedDirectionIndicator
        change (if threshold ≤ support.card ∧ ¬ CodeOn point degree (directionWord data direction) support
            then Nat.choose support.card queryCount else 0) +
          (if CodeOn point degree (directionWord data direction) support then 1 else 0) *
            Nat.choose support.card queryCount = _
        by_cases coded : CodeOn point degree (directionWord data direction) support
        · simp only [coded, not_true_eq_false, and_false, ↓reduceIte, one_mul, zero_add]
        · simp only [coded, not_false_eq_true, and_true, if_pos failure.1, ↓reduceIte,
            Nat.zero_mul, Nat.add_zero]
      simp only [term, Finset.sum_const, Finset.card_univ, smul_eq_mul]
    have fieldPositive : 0 < Fintype.card F := Fintype.card_pos
    have fieldSplit : Fintype.card F - 1 + 1 = Fintype.card F := by omega
    have weighted := Nat.mul_le_mul_right (Nat.choose support.card queryCount) missed
    have expanded := congrArg (fun value => value * Fintype.card F) partition
    have splitWeighted : Fintype.card (Index → F) * (Fintype.card F - 1) *
          Nat.choose support.card queryCount +
        Fintype.card (Index → F) * Nat.choose support.card queryCount =
        Fintype.card (Index → F) * Nat.choose support.card queryCount * Fintype.card F := by
      calc
        _ = Fintype.card (Index → F) * Nat.choose support.card queryCount *
            (Fintype.card F - 1 + 1) := by ring
        _ = _ := by rw [fieldSplit]
    have claimed : Fintype.card (Index → F) * (Fintype.card F - 1) *
        Nat.choose support.card queryCount ≤
      (∑ direction : Index → F,
        detectedWeight point degree threshold queryCount data masks response direction matrix) *
          Fintype.card F := by
      nlinarith only [weighted, expanded, splitWeighted]
    simpa only [if_pos failure] using claimed
  · simp only [if_neg failure, Nat.mul_zero, Nat.zero_le]

omit [DecidableEq Index] [Fintype F] [Fintype Row] [DecidableEq Row] in
theorem zero_direction_detected_weight (point : Position → F) (degree threshold queryCount : ℕ)
    (data : Index → Position → F) (masks : Row → Position → F)
    (response : (Index → Row → F) → BoundedResponse F Row degree)
    (matrix : Index → Row → F) :
    detectedWeight point degree threshold queryCount data masks response 0 matrix = 0 := by
  classical
  have coded : CodeOn point degree (directionWord data 0)
      (sourceSupport point degree data masks response matrix) := by
    refine ⟨0, by simp, ?_⟩
    intro index _
    simp [directionWord]
  unfold detectedWeight
  change (if _ ∧ ¬ CodeOn point degree (directionWord data 0)
      (sourceSupport point degree data masks response matrix) then _ else 0) = 0
  simp only [coded, not_true_eq_false, and_false, ↓reduceIte]

theorem detected_weight_sum_bound_all_directions (point : Position → F)
    (degree threshold queryCount : ℕ)
    (data : Index → Position → F) (masks : Row → Position → F)
    (response : (Index → Row → F) → BoundedResponse F Row degree)
    (direction : Index → F) :
    (∑ matrix : Index → Row → F,
      detectedWeight point degree threshold queryCount data masks response direction matrix) *
        Fintype.card (Row → F) ≤ Fintype.card (Index → Row → F) *
          universalLineBudget (Row := Row) point degree threshold queryCount := by
  classical
  by_cases zero : direction = 0
  · subst direction
    simp only [zero_direction_detected_weight, Finset.sum_const_zero, Nat.zero_mul, Nat.zero_le]
  · have existsPivot : ∃ pivot, direction pivot ≠ 0 := by
      by_contra absent
      push Not at absent
      exact zero (funext absent)
    obtain ⟨pivot, nonzero⟩ := existsPivot
    exact detected_weight_sum_bound point degree threshold queryCount data masks response direction pivot nonzero

/-- Averaging both independent coordinates removes the source-column union
factor. All directions, including zero, are used only in this counting proof. -/
theorem large_failure_weight_sum_bound (point : Position → F)
    (degree threshold queryCount : ℕ) (thresholdValid : degree < threshold)
    (data : Index → Position → F) (masks : Row → Position → F)
    (response : (Index → Row → F) → BoundedResponse F Row degree) :
    (Fintype.card F - 1) * Fintype.card (Row → F) *
        (∑ matrix : Index → Row → F,
          largeFailureWeight point degree threshold queryCount data masks response matrix) ≤
      Fintype.card (Index → Row → F) *
        universalLineBudget (Row := Row) point degree threshold queryCount * Fintype.card F := by
  classical
  have detected : Fintype.card (Index → F) * (Fintype.card F - 1) *
      (∑ matrix : Index → Row → F,
        largeFailureWeight point degree threshold queryCount data masks response matrix) ≤
      (∑ matrix : Index → Row → F, ∑ direction : Index → F,
        detectedWeight point degree threshold queryCount data masks response direction matrix) *
          Fintype.card F := by
    rw [Finset.mul_sum, Finset.sum_mul]
    exact Finset.sum_le_sum fun matrix _ =>
      large_failure_detected_weight_bound point degree threshold queryCount thresholdValid
        data masks response matrix
  have lines : (∑ matrix : Index → Row → F, ∑ direction : Index → F,
      detectedWeight point degree threshold queryCount data masks response direction matrix) *
        Fintype.card (Row → F) ≤
      Fintype.card (Index → F) * (Fintype.card (Index → Row → F) *
        universalLineBudget (Row := Row) point degree threshold queryCount) := by
    rw [Finset.sum_comm, Finset.sum_mul]
    calc
      _ ≤ ∑ _direction : Index → F, Fintype.card (Index → Row → F) *
          universalLineBudget (Row := Row) point degree threshold queryCount := by
        exact Finset.sum_le_sum fun direction _ =>
          detected_weight_sum_bound_all_directions point degree threshold queryCount
            data masks response direction
      _ = _ := by simp only [Finset.sum_const, Finset.card_univ, smul_eq_mul]
  have total : Fintype.card (Index → F) * (Fintype.card F - 1) *
      (∑ matrix : Index → Row → F,
        largeFailureWeight point degree threshold queryCount data masks response matrix) *
        Fintype.card (Row → F) ≤ Fintype.card (Index → F) *
          (Fintype.card (Index → Row → F) *
            universalLineBudget (Row := Row) point degree threshold queryCount) *
              Fintype.card F := by
    calc
      _ ≤ (∑ matrix : Index → Row → F, ∑ direction : Index → F,
          detectedWeight point degree threshold queryCount data masks response direction matrix) *
            Fintype.card F * Fintype.card (Row → F) :=
        Nat.mul_le_mul_right (Fintype.card (Row → F)) detected
      _ = (∑ matrix : Index → Row → F, ∑ direction : Index → F,
          detectedWeight point degree threshold queryCount data masks response direction matrix) *
            Fintype.card (Row → F) * Fintype.card F := by ring
      _ ≤ _ := Nat.mul_le_mul_right (Fintype.card F) lines
  have cancellation : Fintype.card (Index → F) *
      ((Fintype.card F - 1) * Fintype.card (Row → F) *
        (∑ matrix : Index → Row → F,
          largeFailureWeight point degree threshold queryCount data masks response matrix)) ≤
      Fintype.card (Index → F) * (Fintype.card (Index → Row → F) *
        universalLineBudget (Row := Row) point degree threshold queryCount * Fintype.card F) := by
    nlinarith only [total]
  exact Nat.le_of_mul_le_mul_left cancellation Fintype.card_pos

def sourceFailureWeight (point : Position → F) (degree queryCount : ℕ)
    (data : Index → Position → F) (masks : Row → Position → F)
    (response : (Index → Row → F) → BoundedResponse F Row degree)
    (matrix : Index → Row → F) : ℕ := by
  classical
  exact if SourceRecovered point degree data masks response matrix then 0
    else Nat.choose (sourceSupport point degree data masks response matrix).card queryCount

omit [DecidableEq Index] [Fintype F] [Fintype Row] [DecidableEq Row] in
theorem source_failure_weight_le_small_plus_large (point : Position → F)
    (degree threshold queryCount : ℕ)
    (data : Index → Position → F) (masks : Row → Position → F)
    (response : (Index → Row → F) → BoundedResponse F Row degree)
    (matrix : Index → Row → F) :
    sourceFailureWeight point degree queryCount data masks response matrix ≤
      Nat.choose (threshold - 1) queryCount +
        largeFailureWeight point degree threshold queryCount data masks response matrix := by
  classical
  by_cases recovered : SourceRecovered point degree data masks response matrix
  · simp only [sourceFailureWeight, if_pos recovered, Nat.zero_le]
  · by_cases large : threshold ≤ (sourceSupport point degree data masks response matrix).card
    · have failure : threshold ≤ (sourceSupport point degree data masks response matrix).card ∧
          ¬ SourceRecovered point degree data masks response matrix := ⟨large, recovered⟩
      simp only [sourceFailureWeight, if_neg recovered, largeFailureWeight,
        if_pos failure, Nat.le_add_left]
    · have small : (sourceSupport point degree data masks response matrix).card ≤ threshold - 1 := by omega
      exact (show sourceFailureWeight point degree queryCount data masks response matrix ≤
          Nat.choose (threshold - 1) queryCount by
        rw [sourceFailureWeight, if_neg recovered]
        exact Nat.choose_le_choose queryCount small).trans (Nat.le_add_right _ _)

/-- A factor-free finite source/query numerator bound. This contains a defined
maximum over actual line responses, not an unproved numerical budget premise. -/
theorem source_failure_weight_sum_bound (point : Position → F)
    (degree threshold queryCount : ℕ) (thresholdValid : degree < threshold)
    (data : Index → Position → F) (masks : Row → Position → F)
    (response : (Index → Row → F) → BoundedResponse F Row degree) :
    (Fintype.card F - 1) * Fintype.card (Row → F) *
        (∑ matrix : Index → Row → F,
          sourceFailureWeight point degree queryCount data masks response matrix) ≤
      Fintype.card (Index → Row → F) *
        ((Fintype.card F - 1) * Fintype.card (Row → F) * Nat.choose (threshold - 1) queryCount +
          Fintype.card F * universalLineBudget (Row := Row) point degree threshold queryCount) := by
  classical
  have pointwise := Finset.sum_le_sum (fun matrix (_ : matrix ∈ (Finset.univ : Finset (Index → Row → F))) =>
    source_failure_weight_le_small_plus_large point degree threshold queryCount data masks response matrix)
  simp only [Finset.sum_add_distrib, Finset.sum_const, Finset.card_univ, smul_eq_mul] at pointwise
  have scaled := Nat.mul_le_mul_left ((Fintype.card F - 1) * Fintype.card (Row → F)) pointwise
  have large := large_failure_weight_sum_bound point degree threshold queryCount thresholdValid
    data masks response
  nlinarith only [scaled, large]

end

noncomputable section ExactProbability

variable {F Position Row : Type*} [Field F] [Fintype F]
  [Fintype Position] [Fintype Row] [DecidableEq Row]

omit [Fintype F] [Fintype Position] [Fintype Row] [DecidableEq Row] in
theorem finite_source_mixture_eq {count : ℕ}
    (data : ℕ → Position → F) (masks : Row → Position → F)
    (coefficients : Fin count → Row → F) :
    sourceMixture (fun column : Fin count => data column.val) masks coefficients =
      mixedWord data masks (extendCoefficients coefficients) count := by
  funext row index
  rw [mixed_word_eq_sum]
  unfold sourceMixture
  rw [← Fin.sum_univ_eq_sum_range]
  congr 1
  apply Finset.sum_congr rfl
  intro column _
  simp only [extendCoefficients, dif_pos column.isLt]

omit [Fintype F] [Fintype Row] [DecidableEq Row] in
theorem finite_source_failure_weight_eq {count : ℕ}
    (point : Position → F) (degree queryCount : ℕ)
    (data : ℕ → Position → F) (masks : Row → Position → F)
    (response : (Fin count → Row → F) → BoundedResponse F Row degree)
    (coefficients : Fin count → Row → F) :
    sourceFailureWeight point degree queryCount (fun column : Fin count => data column.val)
        masks response coefficients =
      unrecoveredQueryWeight point degree queryCount data masks response coefficients := by
  classical
  have allColumns (support : Finset Position) :
      (∀ column : Fin count, CodeOn point degree (data column.val) support) ↔
        ∀ column < count, CodeOn point degree (data column) support := by
    constructor
    · intro coded column bound
      exact coded ⟨column, bound⟩
    · intro coded column
      exact coded column.val column.isLt
  simp only [sourceFailureWeight, SourceRecovered, sourceSupport, finite_source_mixture_eq,
    allColumns, unrecoveredQueryWeight]

/-- The exact same computed-decoder event as the column proof, with the
column union factor removed by the independent auxiliary-direction count. -/
theorem factor_free_source_recovery_probability_le
    (point : Position → F) (degree threshold queryCount : ℕ)
    (thresholdValid : degree < threshold)
    (sampleFits : queryCount ≤ Fintype.card Position)
    (data : ℕ → Position → F) (masks : Row → Position → F) {count : ℕ}
    (response : (Fin count → Row → F) → BoundedResponse F Row degree) :
    V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability
        (unrecoveredQueryEvent point degree queryCount data masks response) ≤
      (Nat.choose (threshold - 1) queryCount : Rat) /
          Nat.choose (Fintype.card Position) queryCount +
        (Fintype.card F : Rat) * universalLineBudget (Row := Row) point degree threshold queryCount /
          (((Fintype.card F - 1 : ℕ) : Rat) * Fintype.card (Row → F) *
            Nat.choose (Fintype.card Position) queryCount) := by
  classical
  rw [unrecovered_query_probability_exact]
  have counted := source_failure_weight_sum_bound point degree threshold queryCount thresholdValid
    (fun column : Fin count => data column.val) masks response
  simp only [finite_source_failure_weight_eq] at counted
  have fieldCard : 1 < Fintype.card F := Fintype.one_lt_card
  have factorPositive : (0 : Rat) < ((Fintype.card F - 1 : ℕ) : Rat) * Fintype.card (Row → F) := by
    have leftPositive : 0 < Fintype.card F - 1 := by omega
    have rightPositive : 0 < Fintype.card (Row → F) := Fintype.card_pos
    exact_mod_cast Nat.mul_pos leftPositive rightPositive
  have prefixPositive : (0 : Rat) < Fintype.card (Fin count → Row → F) := by
    exact_mod_cast Fintype.card_pos
  have samplePositive : (0 : Rat) < Nat.choose (Fintype.card Position) queryCount := by
    exact_mod_cast Nat.choose_pos sampleFits
  have boundRat :
      (((Fintype.card F - 1 : ℕ) : Rat) * Fintype.card (Row → F)) *
        (∑ coefficients : Fin count → Row → F,
          (unrecoveredQueryWeight point degree queryCount data masks response coefficients : Rat)) ≤
      (Fintype.card (Fin count → Row → F) : Rat) *
        (((Fintype.card F - 1 : ℕ) : Rat) * Fintype.card (Row → F) *
            Nat.choose (threshold - 1) queryCount +
          (Fintype.card F : Rat) * universalLineBudget (Row := Row) point degree threshold queryCount) := by
    exact_mod_cast counted
  apply (div_le_iff₀ (mul_pos prefixPositive samplePositive)).2
  have ratioIdentity (a b c d e : Rat) (aNonzero : a ≠ 0) (bNonzero : b ≠ 0) :
      (c / b + d / (a * b)) * (e * b) = e * (a * c + d) / a := by
    field_simp
  have identity :
      ((Nat.choose (threshold - 1) queryCount : Rat) /
          Nat.choose (Fintype.card Position) queryCount +
        (Fintype.card F : Rat) * universalLineBudget (Row := Row) point degree threshold queryCount /
          (((Fintype.card F - 1 : ℕ) : Rat) * Fintype.card (Row → F) *
            Nat.choose (Fintype.card Position) queryCount)) *
        ((Fintype.card (Fin count → Row → F) : Rat) *
          Nat.choose (Fintype.card Position) queryCount) =
      ((Fintype.card (Fin count → Row → F) : Rat) *
        (((Fintype.card F - 1 : ℕ) : Rat) * Fintype.card (Row → F) *
          Nat.choose (threshold - 1) queryCount +
          (Fintype.card F : Rat) * universalLineBudget (Row := Row) point degree threshold queryCount)) /
        (((Fintype.card F - 1 : ℕ) : Rat) * Fintype.card (Row → F)) := by
    exact ratioIdentity _ _ _ _ _ factorPositive.ne' samplePositive.ne'
  rw [identity]
  exact (le_div_iff₀ factorPositive).2 (by simpa only [mul_comm] using boundRat)

end ExactProbability

noncomputable section CurrentSource

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9RobustQueryMismatch V8Smz9McaDecoder V8Smz9McaDecoder.SourceBinding

theorem smz9_factor_free_recovery_probability_le
    (data : ℕ → Smz9Position → Goldilocks) (masks : Fin 5 → Smz9Position → Goldilocks)
    (response : Smz9Coefficients → BoundedResponse Goldilocks (Fin 5) 387) :
    FiniteEvents.jointProbability
        (unrecoveredQueryEvent V8Smz9DisjointCoset.evaluationPoint 387 20 data masks response) ≤
      (Nat.choose 415 20 : Rat) / Nat.choose (2 ^ 23) 20 +
        (goldilocksModulus : Rat) * smz9LineBudget /
          (((goldilocksModulus - 1 : ℕ) : Rat) * (goldilocksModulus : Rat) ^ 5 *
            Nat.choose (2 ^ 23) 20) := by
  have coefficientCard : Fintype.card (Fin 5 → Goldilocks) = goldilocksModulus ^ 5 := by
    rw [Fintype.card_fun, Fintype.card_fin, goldilocks_card]
  have sampleFits : 20 ≤ Fintype.card Smz9Position := by
    rw [Fintype.card_fin]
    decide
  have bound := factor_free_source_recovery_probability_le
    V8Smz9DisjointCoset.evaluationPoint 387 416 20 (by decide) sampleFits data masks response
  rw [coefficientCard, goldilocks_card, Fintype.card_fin, Nat.cast_pow] at bound
  exact bound

/-- The original source-layout matrix, original response-dependent computed
decoder and exact original twenty-subset, now with no source-column factor. -/
theorem source_decoder_failure_probability_factor_free (source : Source) (response : Response)
    (bounded : ∀ matrix row, (response matrix row).natDegree ≤ 387) :
    FiniteEvents.jointProbability (matrixDecoderFailureEvent source response bounded) ≤
      (Nat.choose 415 20 : Rat) / Nat.choose (2 ^ 23) 20 +
        (goldilocksModulus : Rat) * smz9LineBudget /
          (((goldilocksModulus - 1 : ℕ) : Rat) * (goldilocksModulus : Rat) ^ 5 *
            Nat.choose (2 ^ 23) 20) := by
  have sameProbability :
      FiniteEvents.jointProbability (matrixDecoderFailureEvent source response bounded) =
        FiniteEvents.jointProbability (decoderFailureEvent V8Smz9DisjointCoset.evaluationPoint
          387 20 (sourceData source) source.masks (boundedMatrixResponse response bounded)) := by
    unfold FiniteEvents.jointProbability
    rw [Fintype.card_congr (matrixFailureEquiv source response bounded),
      Fintype.card_congr matrixCoefficientEquiv]
    congr 1
  rw [sameProbability]
  have sameEvents : decoderFailureEvent V8Smz9DisjointCoset.evaluationPoint
      387 20 (sourceData source) source.masks (boundedMatrixResponse response bounded) =
      unrecoveredQueryEvent V8Smz9DisjointCoset.evaluationPoint
        387 20 (sourceData source) source.masks (boundedMatrixResponse response bounded) := by
    funext coefficients
    exact decoder_failure_event_eq_unrecovered_event V8Smz9DisjointCoset.evaluationPoint
      V8Smz9DisjointCoset.evaluation_point_injective 387 20 (sourceData source) source.masks
      (boundedMatrixResponse response bounded) coefficients
  rw [sameEvents]
  exact smz9_factor_free_recovery_probability_le (sourceData source) source.masks
    (boundedMatrixResponse response bounded)

end CurrentSource

end HegemonCrypto.SmallWood.V8Smz9RandomDirectionRecovery
