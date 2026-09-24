import HegemonCrypto.SmallWoodV8Smz9PiecewiseCoverage
import HegemonCrypto.SmallWoodV8Smz9JointQuerySampling

/-!
# Recovering every source word by reversing column combinations

The source words are arbitrary, not supplied with a global polynomial patch
cover. A local line-agreement property is defined against every response's
actual full agreement set. When it holds at each column, reverse induction
recovers every source word on the original final agreement set. Intermediate
agreement sets may enlarge; no step may shrink the retained original support.

The finite product-space theorem counts every coefficient-dependent response
and the fresh exact-cardinality query subset. It reduces recovery failure to
an explicitly defined maximum weighted line budget, without a source-cover
or local-goodness assumption. The concrete Goldilocks bound on that budget
remains unproved. Recovery from a supplied table is not yet quantum extraction
from proof bytes.
-/

namespace HegemonCrypto.SmallWood.V8Smz9McaRecovery

open Polynomial
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped BigOperators

noncomputable section

set_option maxRecDepth 5000

section Recovery

variable {F Position Row : Type*} [Field F] [Fintype Position]

/-- A bounded polynomial reproduces the word on this support only. -/
def CodeOn (point : Position → F) (degree : ℕ) (word : Position → F)
    (support : Finset Position) : Prop :=
  ∃ polynomial : F[X], polynomial.natDegree ≤ degree ∧
    ∀ index ∈ support, polynomial.eval (point index) = word index

def VectorCodeOn (point : Position → F) (degree : ℕ)
    (words : Row → Position → F) (support : Finset Position) : Prop :=
  ∀ row, CodeOn point degree (words row) support

omit [Fintype Position] in
theorem code_on_mono (point : Position → F) (degree : ℕ) (word : Position → F)
    {small large : Finset Position} (subset : small ⊆ large)
    (coded : CodeOn point degree word large) : CodeOn point degree word small := by
  obtain ⟨polynomial, bounded, agrees⟩ := coded
  exact ⟨polynomial, bounded, fun index member => agrees index (subset member)⟩

omit [Fintype Position] in
theorem code_on_sub_smul (point : Position → F) (degree : ℕ)
    (left right : Position → F) (support : Finset Position) (scalar : F)
    (leftCode : CodeOn point degree left support)
    (rightCode : CodeOn point degree right support) :
    CodeOn point degree (fun index => left index - scalar * right index) support := by
  obtain ⟨leftPolynomial, leftBound, leftAgrees⟩ := leftCode
  obtain ⟨rightPolynomial, rightBound, rightAgrees⟩ := rightCode
  refine ⟨leftPolynomial - C scalar * rightPolynomial, ?_, ?_⟩
  · exact (natDegree_sub_le _ _).trans
      (max_le leftBound ((natDegree_C_mul_le _ _).trans rightBound))
  · intro index member
    simp only [eval_sub, eval_mul, eval_C, leftAgrees index member, rightAgrees index member]

def lineWord (prior : Row → Position → F) (direction : Position → F)
    (coefficient : Row → F) : Row → Position → F :=
  fun row index => prior row index + coefficient row * direction index

def agreement (point : Position → F) (word : Row → Position → F)
    (response : Row → F[X]) : Finset Position := by
  classical
  exact Finset.univ.filter fun index => ∀ row,
    (response row).eval (point index) = word row index

theorem mem_agreement (point : Position → F) (word : Row → Position → F)
    (response : Row → F[X]) (index : Position) :
    index ∈ agreement point word response ↔
      ∀ row, (response row).eval (point index) = word row index := by
  classical
  simp only [agreement, Finset.mem_filter, Finset.mem_univ, true_and]

/-- The local property is universal over responses, before any final query sample. -/
def LineGood (point : Position → F) (degree threshold : ℕ)
    (prior : Row → Position → F) (direction : Position → F)
    (coefficient : Row → F) : Prop :=
  ∀ response : Row → F[X],
    (∀ row, (response row).natDegree ≤ degree) →
    threshold ≤ (agreement point (lineWord prior direction coefficient) response).card →
    CodeOn point degree direction
      (agreement point (lineWord prior direction coefficient) response)

/-- Full agreement may enlarge, but the original support is retained in both recovered words. -/
theorem reverse_one_column (point : Position → F) (degree threshold : ℕ)
    (prior : Row → Position → F) (direction : Position → F)
    (coefficient : Row → F) (support : Finset Position)
    (large : threshold ≤ support.card)
    (good : LineGood point degree threshold prior direction coefficient)
    (combinedCode : VectorCodeOn point degree (lineWord prior direction coefficient) support) :
    CodeOn point degree direction support ∧
      VectorCodeOn point degree prior support := by
  classical
  choose response bounded agrees using combinedCode
  have subset : support ⊆ agreement point (lineWord prior direction coefficient) response := by
    intro index member
    rw [mem_agreement]
    exact fun row => agrees row index member
  have directionCode := code_on_mono point degree direction subset
    (good response bounded (large.trans (Finset.card_le_card subset)))
  refine ⟨directionCode, fun row => ?_⟩
  have previous := code_on_sub_smul point degree
    ((lineWord prior direction coefficient) row) direction support (coefficient row)
    ⟨response row, bounded row, agrees row⟩ directionCode
  simpa only [lineWord, add_sub_cancel_right] using previous

/-- Column combinations in chronological order; the mask word is the initial state. -/
def mixedWord (data : ℕ → Position → F) (masks : Row → Position → F)
    (coefficients : ℕ → Row → F) : ℕ → Row → Position → F
  | 0 => masks
  | count + 1 => lineWord (mixedWord data masks coefficients count)
      (data count) (coefficients count)

omit [Fintype Position] in
theorem mixed_word_eq_sum (data : ℕ → Position → F) (masks : Row → Position → F)
    (coefficients : ℕ → Row → F) (count : ℕ) (row : Row) (index : Position) :
    mixedWord data masks coefficients count row index =
      masks row index + ∑ column ∈ Finset.range count,
        coefficients column row * data column index := by
  induction count with
  | zero => simp only [mixedWord, Finset.range_zero, Finset.sum_empty, add_zero]
  | succ count inductionHypothesis =>
      simp only [mixedWord, lineWord, inductionHypothesis, Finset.sum_range_succ]
      exact add_assoc _ _ _

/-- Reverse all columns without a source-cover or a post-query candidate hypothesis. -/
theorem reverse_all_columns (point : Position → F) (degree threshold : ℕ)
    (data : ℕ → Position → F) (masks : Row → Position → F)
    (coefficients : ℕ → Row → F) (count : ℕ) (support : Finset Position)
    (large : threshold ≤ support.card)
    (good : ∀ column < count, LineGood point degree threshold
      (mixedWord data masks coefficients column) (data column) (coefficients column))
    (combinedCode : VectorCodeOn point degree
      (mixedWord data masks coefficients count) support) :
    VectorCodeOn point degree masks support ∧
      ∀ column < count, CodeOn point degree (data column) support := by
  induction count with
  | zero => exact ⟨combinedCode, fun column impossible => False.elim (Nat.not_lt_zero _ impossible)⟩
  | succ count inductionHypothesis =>
      obtain ⟨lastCode, previousCode⟩ := reverse_one_column point degree threshold
        (mixedWord data masks coefficients count) (data count) (coefficients count)
        support large (good count (Nat.lt_succ_self _)) combinedCode
      obtain ⟨maskCode, earlierCode⟩ := inductionHypothesis
        (fun column before => good column (Nat.lt_succ_of_lt before)) previousCode
      refine ⟨maskCode, fun column before => ?_⟩
      rcases Nat.lt_or_eq_of_le (Nat.le_of_lt_succ before) with earlier | same
      · exact earlierCode column earlier
      · simpa only [same] using lastCode

/-- Apply the reverse procedure to the response's actual full agreement set. -/
theorem response_agreement_recovers_all_source_words
    (point : Position → F) (degree threshold : ℕ)
    (data : ℕ → Position → F) (masks : Row → Position → F)
    (coefficients : ℕ → Row → F) (count : ℕ) (response : Row → F[X])
    (bounded : ∀ row, (response row).natDegree ≤ degree)
    (large : threshold ≤
      (agreement point (mixedWord data masks coefficients count) response).card)
    (good : ∀ column < count, LineGood point degree threshold
      (mixedWord data masks coefficients column) (data column) (coefficients column)) :
    VectorCodeOn point degree masks
      (agreement point (mixedWord data masks coefficients count) response) ∧
    ∀ column < count, CodeOn point degree (data column)
      (agreement point (mixedWord data masks coefficients count) response) := by
  apply reverse_all_columns point degree threshold data masks coefficients count _ large good
  intro row
  refine ⟨response row, bounded row, ?_⟩
  intro index member
  exact (mem_agreement point _ response index).mp member row

end Recovery

section FiniteWeights

variable {F Position Row : Type*} [Field F] [Fintype F]
  [Fintype Position] [Fintype Row]

/-- A genuinely finite response space, encoded by degree-plus-one coefficients per row. -/
abbrev BoundedResponse (F Row : Type*) [Field F] (degree : ℕ) :=
  Row → Polynomial.degreeLT F (degree + 1)

noncomputable instance boundedPolynomialFintype (degree : ℕ) :
    Fintype (Polynomial.degreeLT F (degree + 1)) :=
  Fintype.ofEquiv (Fin (degree + 1) → F) (Polynomial.degreeLTEquiv F (degree + 1)).symm.toEquiv

def responsePolynomials {degree : ℕ} (response : BoundedResponse F Row degree) : Row → F[X] :=
  fun row => (response row).val

omit [Fintype F] [Fintype Row] in
theorem bounded_response_degree {degree : ℕ} (response : BoundedResponse F Row degree)
    (row : Row) : (responsePolynomials response row).natDegree ≤ degree := by
  by_cases zero : responsePolynomials response row = 0
  · simp only [zero, natDegree_zero, Nat.zero_le]
  · have degreeBound := Polynomial.mem_degreeLT.mp (response row).property
    exact Nat.le_of_lt_succ ((Polynomial.natDegree_lt_iff_degree_lt zero).mpr degreeBound)

def boundedResponseOfPolynomials {degree : ℕ} (response : Row → F[X])
    (bounded : ∀ row, (response row).natDegree ≤ degree) : BoundedResponse F Row degree :=
  fun row => ⟨response row, Polynomial.mem_degreeLT.mpr
    (lt_of_le_of_lt (degree_le_natDegree : (response row).degree ≤ _)
      (by exact_mod_cast Nat.lt_succ_of_le (bounded row)))⟩

omit [Fintype F] [Fintype Row] in
theorem bounded_response_roundtrip {degree : ℕ} (response : Row → F[X])
    (bounded : ∀ row, (response row).natDegree ≤ degree) :
    responsePolynomials (boundedResponseOfPolynomials response bounded) = response := rfl

/-- Number of final query subsets exposed by one bad full-agreement response. -/
def badResponseWeight (point : Position → F) (degree threshold queryCount : ℕ)
    (prior : Row → Position → F) (direction : Position → F) (coefficient : Row → F)
    (response : BoundedResponse F Row degree) : ℕ := by
  classical
  let support := agreement point (lineWord prior direction coefficient)
    (responsePolynomials response)
  exact if threshold ≤ support.card ∧ ¬ CodeOn point degree direction support
    then Nat.choose support.card queryCount else 0

/-- Explicit maximum over the finite response space, not an asserted security probability. -/
def badCoefficientWeight (point : Position → F) (degree threshold queryCount : ℕ)
    (prior : Row → Position → F) (direction : Position → F) (coefficient : Row → F) : ℕ := by
  classical
  exact Finset.univ.sup (badResponseWeight point degree threshold queryCount
    prior direction coefficient)

theorem bad_response_weight_le_coefficient_weight
    (point : Position → F) (degree threshold queryCount : ℕ)
    (prior : Row → Position → F) (direction : Position → F) (coefficient : Row → F)
    (response : BoundedResponse F Row degree) :
    badResponseWeight point degree threshold queryCount prior direction coefficient response ≤
      badCoefficientWeight point degree threshold queryCount prior direction coefficient := by
  classical
  exact Finset.le_sup (f := badResponseWeight point degree threshold queryCount
    prior direction coefficient) (Finset.mem_univ response)

/-- A retained bad support is charged to an actual full agreement, even when that set enlarges. -/
theorem retained_bad_support_weight_le
    (point : Position → F) (degree threshold queryCount : ℕ)
    (prior : Row → Position → F) (direction : Position → F) (coefficient : Row → F)
    (support : Finset Position) (large : threshold ≤ support.card)
    (notCoded : ¬ CodeOn point degree direction support)
    (combinedCode : VectorCodeOn point degree (lineWord prior direction coefficient) support) :
    Nat.choose support.card queryCount ≤
      badCoefficientWeight point degree threshold queryCount prior direction coefficient := by
  classical
  choose response bounded agrees using combinedCode
  let encoded := boundedResponseOfPolynomials response bounded
  have subset : support ⊆ agreement point (lineWord prior direction coefficient) response := by
    intro index member
    rw [mem_agreement]
    exact fun row => agrees row index member
  have fullLarge := large.trans (Finset.card_le_card subset)
  have fullNotCoded : ¬ CodeOn point degree direction
      (agreement point (lineWord prior direction coefficient) response) := by
    intro fullCode
    exact notCoded (code_on_mono point degree direction subset fullCode)
  have weightEq : badResponseWeight point degree threshold queryCount
      prior direction coefficient encoded =
      Nat.choose (agreement point (lineWord prior direction coefficient) response).card
        queryCount := by
    simp only [badResponseWeight, encoded, bounded_response_roundtrip]
    rw [if_pos ⟨fullLarge, fullNotCoded⟩]
  calc
    Nat.choose support.card queryCount ≤
        Nat.choose (agreement point (lineWord prior direction coefficient) response).card
          queryCount := Nat.choose_le_choose queryCount (Finset.card_le_card subset)
    _ = badResponseWeight point degree threshold queryCount prior direction coefficient encoded :=
      weightEq.symm
    _ ≤ badCoefficientWeight point degree threshold queryCount prior direction coefficient :=
      bad_response_weight_le_coefficient_weight point degree threshold queryCount
        prior direction coefficient encoded

/-- The exact (unnormalized) coefficient budget to be bounded by the numerical MCA theorem. -/
def lineCoefficientBudget (point : Position → F) (degree threshold queryCount : ℕ)
    (prior : Row → Position → F) (direction : Position → F) : ℕ := by
  classical
  exact ∑ coefficient : Row → F,
    badCoefficientWeight point degree threshold queryCount prior direction coefficient

/-- A finite worst-case constant over actual source functions. Its value is not postulated. -/
def universalLineBudget (point : Position → F) (degree threshold queryCount : ℕ) : ℕ := by
  classical
  exact Finset.univ.sup fun prior : Row → Position → F =>
    Finset.univ.sup fun direction : Position → F =>
      lineCoefficientBudget point degree threshold queryCount prior direction

theorem line_budget_le_universal
    (point : Position → F) (degree threshold queryCount : ℕ)
    (prior : Row → Position → F) (direction : Position → F) :
    lineCoefficientBudget point degree threshold queryCount prior direction ≤
      universalLineBudget (Row := Row) point degree threshold queryCount := by
  classical
  apply (Finset.le_sup (f := fun direction : Position → F =>
    lineCoefficientBudget point degree threshold queryCount prior direction)
    (Finset.mem_univ direction)).trans
  exact Finset.le_sup (f := fun prior : Row → Position → F =>
    Finset.univ.sup fun direction : Position → F =>
      lineCoefficientBudget point degree threshold queryCount prior direction)
    (Finset.mem_univ prior)

/-- Failure to recover the fixed source on a retained support is charged to actual column weights.
No local-goodness or source-cover premise is supplied to this inequality. -/
theorem unrecovered_support_weight_le_column_sum
    (point : Position → F) (degree threshold queryCount : ℕ)
    (data : ℕ → Position → F) (masks : Row → Position → F)
    (coefficients : ℕ → Row → F) (count : ℕ) (support : Finset Position)
    (large : threshold ≤ support.card)
    (combinedCode : VectorCodeOn point degree
      (mixedWord data masks coefficients count) support)
    (notRecovered : ¬ (VectorCodeOn point degree masks support ∧
      ∀ column < count, CodeOn point degree (data column) support)) :
    Nat.choose support.card queryCount ≤
      ∑ column ∈ Finset.range count,
        badCoefficientWeight point degree threshold queryCount
          (mixedWord data masks coefficients column) (data column) (coefficients column) := by
  classical
  induction count with
  | zero =>
      exact False.elim (notRecovered ⟨combinedCode,
        fun column impossible => False.elim (Nat.not_lt_zero _ impossible)⟩)
  | succ count inductionHypothesis =>
      rw [Finset.sum_range_succ]
      by_cases directionCode : CodeOn point degree (data count) support
      · have previousCode : VectorCodeOn point degree
            (mixedWord data masks coefficients count) support := by
          intro row
          have subtracted := code_on_sub_smul point degree
            (mixedWord data masks coefficients (count + 1) row)
            (data count) support (coefficients count row) (combinedCode row) directionCode
          simpa only [mixedWord, lineWord, add_sub_cancel_right] using subtracted
        have previousFailure : ¬ (VectorCodeOn point degree masks support ∧
            ∀ column < count, CodeOn point degree (data column) support) := by
          rintro ⟨maskCode, earlierCode⟩
          apply notRecovered
          refine ⟨maskCode, fun column before => ?_⟩
          rcases Nat.lt_or_eq_of_le (Nat.le_of_lt_succ before) with earlier | same
          · exact earlierCode column earlier
          · simpa only [same] using directionCode
        exact (inductionHypothesis previousCode previousFailure).trans (Nat.le_add_right _ _)
      · exact (retained_bad_support_weight_le point degree threshold queryCount
          (mixedWord data masks coefficients count) (data count) (coefficients count)
          support large directionCode combinedCode).trans (Nat.le_add_left _ _)

end FiniteWeights

section ProductCounting

variable {Index Coefficient : Type*} [Fintype Index] [DecidableEq Index]
  [Fintype Coefficient] [Nonempty Coefficient]

/-- Exact uniform-product marginal counting; the cost may depend on every other coordinate. -/
theorem coordinate_sum_bound (index : Index) (cost : (Index → Coefficient) → ℕ)
    (budget : ℕ)
    (fiberBound : ∀ assignment,
      (∑ value : Coefficient, cost (Function.update assignment index value)) ≤ budget) :
    (∑ assignment : Index → Coefficient, cost assignment) * Fintype.card Coefficient ≤
      Fintype.card (Index → Coefficient) * budget := by
  classical
  let split := Equiv.funSplitAt index Coefficient
  let baseline : Coefficient := Classical.choice inferInstance
  have fiber (rest : { other : Index // other ≠ index } → Coefficient) :
      (∑ value : Coefficient, cost (split.symm (value, rest))) ≤ budget := by
    have updateEq (value : Coefficient) :
        Function.update (split.symm (baseline, rest)) index value =
          split.symm (value, rest) := by
      funext other
      by_cases same : other = index
      · subst other
        simp [split, Equiv.funSplitAt, Equiv.piSplitAt]
      · simp [split, Equiv.funSplitAt, Equiv.piSplitAt, same]
    simpa only [updateEq] using fiberBound (split.symm (baseline, rest))
  have sumEq : (∑ assignment : Index → Coefficient, cost assignment) =
      ∑ rest : { other : Index // other ≠ index } → Coefficient,
        ∑ value : Coefficient, cost (split.symm (value, rest)) := by
    rw [Fintype.sum_equiv split cost (fun pair => cost (split.symm pair))
      (fun assignment => by simp)]
    rw [Fintype.sum_prod_type, Finset.sum_comm]
  have total : (∑ assignment : Index → Coefficient, cost assignment) ≤
      Fintype.card ({ other : Index // other ≠ index } → Coefficient) * budget := by
    rw [sumEq]
    exact (Finset.sum_le_sum fun rest _ => fiber rest).trans_eq (by simp)
  have cardinality := Fintype.card_congr split
  simp only [Fintype.card_prod] at cardinality
  calc
    (∑ assignment : Index → Coefficient, cost assignment) * Fintype.card Coefficient ≤
        (Fintype.card ({ other : Index // other ≠ index } → Coefficient) * budget) *
          Fintype.card Coefficient := Nat.mul_le_mul_right _ total
    _ = Fintype.card (Index → Coefficient) * budget := by
      rw [cardinality]
      ac_rfl

end ProductCounting

section ColumnCounting

variable {F Position Row : Type*} [Field F] [Fintype F]
  [Fintype Position] [Fintype Row] [DecidableEq Row]

def extendCoefficients {count : ℕ} (coefficients : Fin count → Row → F) : ℕ → Row → F :=
  fun column => if bounded : column < count then coefficients ⟨column, bounded⟩ else 0

omit [Fintype F] [Fintype Position] [Fintype Row] [DecidableEq Row] in
theorem mixed_word_congr_before (data : ℕ → Position → F) (masks : Row → Position → F)
    (left right : ℕ → Row → F) (count : ℕ)
    (same : ∀ column < count, left column = right column) :
    mixedWord data masks left count = mixedWord data masks right count := by
  induction count with
  | zero => rfl
  | succ count inductionHypothesis =>
      simp only [mixedWord]
      rw [inductionHypothesis (fun column before => same column (Nat.lt_succ_of_lt before)),
        same count (Nat.lt_succ_self _)]

omit [Fintype F] [Fintype Position] [Fintype Row] [DecidableEq Row] in
theorem current_coefficient_does_not_change_prior {count : ℕ}
    (data : ℕ → Position → F) (masks : Row → Position → F)
    (coefficients : Fin count → Row → F) (column : Fin count) (value : Row → F) :
    mixedWord data masks (extendCoefficients (Function.update coefficients column value))
        column.val =
      mixedWord data masks (extendCoefficients coefficients) column.val := by
  classical
  apply mixed_word_congr_before
  intro earlier before
  have bounded : earlier < count := before.trans column.is_lt
  have different : (⟨earlier, bounded⟩ : Fin count) ≠ column := by
    intro same
    have values := congrArg Fin.val same
    change earlier = column.val at values
    omega
  simp only [extendCoefficients, dif_pos bounded, Function.update_of_ne different]

def columnWeight (point : Position → F) (degree threshold queryCount : ℕ)
    (data : ℕ → Position → F) (masks : Row → Position → F) {count : ℕ}
    (column : Fin count) (coefficients : Fin count → Row → F) : ℕ :=
  badCoefficientWeight point degree threshold queryCount
    (mixedWord data masks (extendCoefficients coefficients) column.val)
    (data column.val) (coefficients column)

theorem column_weight_sum_bound
    (point : Position → F) (degree threshold queryCount : ℕ)
    (data : ℕ → Position → F) (masks : Row → Position → F) {count : ℕ}
    (column : Fin count) (budget : ℕ)
    (lineBound : ∀ prior : Row → Position → F,
      lineCoefficientBudget point degree threshold queryCount prior (data column.val) ≤ budget) :
    (∑ coefficients : Fin count → Row → F,
      columnWeight point degree threshold queryCount data masks column coefficients) *
        Fintype.card (Row → F) ≤
      Fintype.card (Fin count → Row → F) * budget := by
  classical
  apply coordinate_sum_bound column _ budget
  intro coefficients
  have updated (value : Row → F) :
      columnWeight point degree threshold queryCount data masks column
          (Function.update coefficients column value) =
        badCoefficientWeight point degree threshold queryCount
          (mixedWord data masks (extendCoefficients coefficients) column.val)
          (data column.val) value := by
    unfold columnWeight
    rw [current_coefficient_does_not_change_prior, Function.update_self]
  simp only [updated]
  have bounded := lineBound
    (mixedWord data masks (extendCoefficients coefficients) column.val)
  unfold lineCoefficientBudget at bounded
  convert bounded using 1
  apply Finset.sum_congr
  · ext value
    simp
  · intro value _
    rfl

/-- Sum every column's actual bad-support weight over the full independent coefficient array. -/
theorem all_column_weights_sum_bound
    (point : Position → F) (degree threshold queryCount : ℕ)
    (data : ℕ → Position → F) (masks : Row → Position → F) {count : ℕ}
    (budget : ℕ)
    (lineBound : ∀ (column : Fin count) (prior : Row → Position → F),
      lineCoefficientBudget point degree threshold queryCount prior (data column.val) ≤ budget) :
    (∑ coefficients : Fin count → Row → F, ∑ column : Fin count,
      columnWeight point degree threshold queryCount data masks column coefficients) *
        Fintype.card (Row → F) ≤
      Fintype.card (Fin count → Row → F) * (count * budget) := by
  classical
  rw [Finset.sum_comm, Finset.sum_mul]
  calc
    _ ≤ ∑ _column : Fin count,
        Fintype.card (Fin count → Row → F) * budget := by
      apply Finset.sum_le_sum
      intro column _
      exact column_weight_sum_bound point degree threshold queryCount data masks column budget
        (lineBound column)
    _ = _ := by simp; ring

/-- Count query subsets accepting the response while some fixed source word has no polynomial
on its full agreement set. The response can depend on the entire coefficient array. -/
def unrecoveredQueryWeight
    (point : Position → F) (degree queryCount : ℕ)
    (data : ℕ → Position → F) (masks : Row → Position → F) {count : ℕ}
    (response : (Fin count → Row → F) → BoundedResponse F Row degree)
    (coefficients : Fin count → Row → F) : ℕ := by
  classical
  let support := agreement point
    (mixedWord data masks (extendCoefficients coefficients) count)
    (responsePolynomials (response coefficients))
  exact if degree < support.card ∧ (VectorCodeOn point degree masks support ∧
      ∀ column < count, CodeOn point degree (data column) support)
    then 0 else Nat.choose support.card queryCount

omit [DecidableEq Row] in
theorem unrecovered_query_weight_le
    (point : Position → F) (degree threshold queryCount : ℕ)
    (thresholdValid : degree < threshold)
    (data : ℕ → Position → F) (masks : Row → Position → F) {count : ℕ}
    (response : (Fin count → Row → F) → BoundedResponse F Row degree)
    (coefficients : Fin count → Row → F) :
    unrecoveredQueryWeight point degree queryCount data masks response coefficients ≤
      Nat.choose (threshold - 1) queryCount + ∑ column : Fin count,
        columnWeight point degree threshold queryCount data masks column coefficients := by
  classical
  let support := agreement point
    (mixedWord data masks (extendCoefficients coefficients) count)
    (responsePolynomials (response coefficients))
  by_cases recovered : degree < support.card ∧ (VectorCodeOn point degree masks support ∧
      ∀ column < count, CodeOn point degree (data column) support)
  · change (if degree < support.card ∧ (VectorCodeOn point degree masks support ∧
        ∀ column < count, CodeOn point degree (data column) support) then 0 else _) ≤ _
    rw [if_pos recovered]
    exact Nat.zero_le _
  · change (if _ then 0 else _) ≤ _
    rw [if_neg recovered]
    by_cases large : threshold ≤ support.card
    · have combinedCode : VectorCodeOn point degree
          (mixedWord data masks (extendCoefficients coefficients) count) support := by
        intro row
        refine ⟨responsePolynomials (response coefficients) row,
          bounded_response_degree (response coefficients) row, ?_⟩
        intro index member
        exact (mem_agreement point _ _ index).mp member row
      have bound := unrecovered_support_weight_le_column_sum point degree threshold queryCount
        data masks (extendCoefficients coefficients) count support large combinedCode
        (fun codes => recovered ⟨thresholdValid.trans_le large, codes⟩)
      have sumEq : (∑ column : Fin count,
          columnWeight point degree threshold queryCount data masks column coefficients) =
          ∑ column ∈ Finset.range count,
            badCoefficientWeight point degree threshold queryCount
              (mixedWord data masks (extendCoefficients coefficients) column)
              (data column) (extendCoefficients coefficients column) := by
        rw [← Fin.sum_univ_eq_sum_range]
        apply Finset.sum_congr rfl
        intro column _
        simp only [columnWeight, extendCoefficients, dif_pos column.isLt]
      rw [sumEq]
      exact bound.trans (Nat.le_add_left _ _)
    · have small : support.card ≤ threshold - 1 := by omega
      exact (Nat.choose_le_choose queryCount small).trans (Nat.le_add_right _ _)

/-- Unconditional finite reduction to the explicitly defined line budget. No polynomial
source cover, local line-goodness, response independence, or numerical MCA claim is assumed. -/
theorem unrecovered_query_weight_sum_bound
    (point : Position → F) (degree threshold queryCount : ℕ)
    (thresholdValid : degree < threshold)
    (data : ℕ → Position → F) (masks : Row → Position → F) {count : ℕ}
    (response : (Fin count → Row → F) → BoundedResponse F Row degree)
    (budget : ℕ)
    (lineBound : ∀ (column : Fin count) (prior : Row → Position → F),
      lineCoefficientBudget point degree threshold queryCount prior (data column.val) ≤ budget) :
    (∑ coefficients : Fin count → Row → F,
      unrecoveredQueryWeight point degree queryCount data masks response coefficients) *
        Fintype.card (Row → F) ≤
      Fintype.card (Fin count → Row → F) *
        (Nat.choose (threshold - 1) queryCount * Fintype.card (Row → F) + count * budget) := by
  classical
  have pointwise := Finset.sum_le_sum (s := (Finset.univ : Finset (Fin count → Row → F)))
    (fun coefficients _ => unrecovered_query_weight_le point degree threshold queryCount
      thresholdValid data masks response coefficients)
  have columns := all_column_weights_sum_bound point degree threshold queryCount
    data masks budget lineBound
  calc
    _ ≤ (∑ coefficients : Fin count → Row → F,
        (Nat.choose (threshold - 1) queryCount + ∑ column : Fin count,
          columnWeight point degree threshold queryCount data masks column coefficients)) *
            Fintype.card (Row → F) := Nat.mul_le_mul_right _ pointwise
    _ = Fintype.card (Fin count → Row → F) * Nat.choose (threshold - 1) queryCount *
          Fintype.card (Row → F) +
        (∑ coefficients : Fin count → Row → F, ∑ column : Fin count,
          columnWeight point degree threshold queryCount data masks column coefficients) *
            Fintype.card (Row → F) := by rw [Finset.sum_add_distrib]; simp; ring
    _ ≤ Fintype.card (Fin count → Row → F) * Nat.choose (threshold - 1) queryCount *
          Fintype.card (Row → F) +
        Fintype.card (Fin count → Row → F) * (count * budget) := Nat.add_le_add_left columns _
    _ = _ := by ring

end ColumnCounting

section ExactQueryExperiment

variable {F Position Row : Type*} [Field F] [Fintype F]
  [Fintype Position] [Fintype Row] [DecidableEq Row]

abbrev QuerySample (Position : Type*) (queryCount : ℕ) :=
  { sample : Finset Position // sample.card = queryCount }

noncomputable instance querySampleFintype (queryCount : ℕ) :
    Fintype (QuerySample Position queryCount) := Fintype.ofFinite _

def sampleWithinEvent (support : Finset Position) (queryCount : ℕ) :
    Finset (QuerySample Position queryCount) := by
  classical
  exact Finset.univ.filter fun sample => sample.val ⊆ support

omit [Field F] [Fintype F] [Fintype Row] [DecidableEq Row] in
theorem sample_within_event_card (support : Finset Position) (queryCount : ℕ) :
    (sampleWithinEvent support queryCount).card = Nat.choose support.card queryCount := by
  classical
  let equivalence : { sample // sample ∈ sampleWithinEvent support queryCount } ≃
      { subset // subset ∈ support.powersetCard queryCount } := {
    toFun := fun sample => ⟨sample.val.val, Finset.mem_powersetCard.mpr
      ⟨(Finset.mem_filter.mp sample.property).2, sample.val.property⟩⟩
    invFun := fun subset => ⟨⟨subset.val, (Finset.mem_powersetCard.mp subset.property).2⟩,
      Finset.mem_filter.mpr ⟨Finset.mem_univ _,
        (Finset.mem_powersetCard.mp subset.property).1⟩⟩
    left_inv := by intro sample; apply Subtype.ext; apply Subtype.ext; rfl
    right_inv := by intro subset; apply Subtype.ext; rfl }
  have counted := Fintype.card_congr equivalence
  simpa only [Fintype.card_coe, Finset.card_powersetCard] using counted

omit [Field F] [Fintype F] [Fintype Row] [DecidableEq Row] in
theorem query_sample_card (queryCount : ℕ) :
    Fintype.card (QuerySample Position queryCount) =
      Nat.choose (Fintype.card Position) queryCount := by
  classical
  have counted := sample_within_event_card (Finset.univ : Finset Position) queryCount
  simpa [sampleWithinEvent] using counted

/-- The actual event has one prefix (all coefficients) and a fresh uniform fixed-size subset. -/
def unrecoveredQueryEvent
    (point : Position → F) (degree queryCount : ℕ)
    (data : ℕ → Position → F) (masks : Row → Position → F) {count : ℕ}
    (response : (Fin count → Row → F) → BoundedResponse F Row degree)
    (coefficients : Fin count → Row → F) : Finset (QuerySample Position queryCount) := by
  classical
  let support := agreement point
    (mixedWord data masks (extendCoefficients coefficients) count)
    (responsePolynomials (response coefficients))
  exact if degree < support.card ∧ (VectorCodeOn point degree masks support ∧
      ∀ column < count, CodeOn point degree (data column) support)
    then ∅ else sampleWithinEvent support queryCount

omit [Fintype F] [Fintype Row] [DecidableEq Row] in
theorem unrecovered_query_event_card
    (point : Position → F) (degree queryCount : ℕ)
    (data : ℕ → Position → F) (masks : Row → Position → F) {count : ℕ}
    (response : (Fin count → Row → F) → BoundedResponse F Row degree)
    (coefficients : Fin count → Row → F) :
    (unrecoveredQueryEvent point degree queryCount data masks response coefficients).card =
      unrecoveredQueryWeight point degree queryCount data masks response coefficients := by
  classical
  dsimp only [unrecoveredQueryEvent, unrecoveredQueryWeight]
  split <;> simp only [Finset.card_empty, sample_within_event_card]

theorem unrecovered_query_probability_exact
    (point : Position → F) (degree queryCount : ℕ)
    (data : ℕ → Position → F) (masks : Row → Position → F) {count : ℕ}
    (response : (Fin count → Row → F) → BoundedResponse F Row degree) :
    V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability
        (unrecoveredQueryEvent point degree queryCount data masks response) =
      (∑ coefficients : Fin count → Row → F,
        (unrecoveredQueryWeight point degree queryCount data masks response coefficients : Rat)) /
        ((Fintype.card (Fin count → Row → F) : Rat) *
          Nat.choose (Fintype.card Position) queryCount) := by
  classical
  unfold V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability
  rw [Fintype.card_sigma, query_sample_card]
  simp only [Fintype.card_coe, unrecovered_query_event_card, Nat.cast_sum]

/-- Source-independent exact finite bound in the complete coefficient/subset product space.
The remaining numerical research problem is the value of `universalLineBudget`, not an
unmentioned source cover or an independence premise about the adaptive response. -/
theorem arbitrary_source_recovery_probability_le
    (point : Position → F) (degree threshold queryCount : ℕ)
    (thresholdValid : degree < threshold)
    (sampleFits : queryCount ≤ Fintype.card Position)
    (data : ℕ → Position → F) (masks : Row → Position → F) {count : ℕ}
    (response : (Fin count → Row → F) → BoundedResponse F Row degree) :
    V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability
        (unrecoveredQueryEvent point degree queryCount data masks response) ≤
      (Nat.choose (threshold - 1) queryCount : Rat) /
          Nat.choose (Fintype.card Position) queryCount +
        (count * (universalLineBudget (Row := Row) point degree threshold queryCount : Rat)) /
          ((Fintype.card (Row → F) : Rat) *
            Nat.choose (Fintype.card Position) queryCount) := by
  classical
  rw [unrecovered_query_probability_exact]
  have counted := unrecovered_query_weight_sum_bound point degree threshold queryCount
    thresholdValid data masks response (universalLineBudget (Row := Row) point degree threshold queryCount)
    (fun column prior => line_budget_le_universal point degree threshold queryCount prior
      (data column.val))
  have boundRat :
      (∑ coefficients : Fin count → Row → F,
        (unrecoveredQueryWeight point degree queryCount data masks response coefficients : Rat)) *
          Fintype.card (Row → F) ≤
        (Fintype.card (Fin count → Row → F) : Rat) *
          ((Nat.choose (threshold - 1) queryCount : Rat) * Fintype.card (Row → F) +
            count * (universalLineBudget (Row := Row) point degree threshold queryCount : Rat)) := by
    exact_mod_cast counted
  have prefixPositive : (0 : Rat) < Fintype.card (Fin count → Row → F) := by
    exact_mod_cast Fintype.card_pos
  have coefficientPositive : (0 : Rat) < Fintype.card (Row → F) := by
    exact_mod_cast Fintype.card_pos
  have samplePositive : (0 : Rat) < Nat.choose (Fintype.card Position) queryCount := by
    exact_mod_cast Nat.choose_pos sampleFits
  apply (div_le_iff₀ (mul_pos prefixPositive samplePositive)).2
  have identity :
      (((Nat.choose (threshold - 1) queryCount : Rat) /
          Nat.choose (Fintype.card Position) queryCount +
        (count * (universalLineBudget (Row := Row) point degree threshold queryCount : Rat)) /
          ((Fintype.card (Row → F) : Rat) *
            Nat.choose (Fintype.card Position) queryCount)) *
          ((Fintype.card (Fin count → Row → F) : Rat) *
            Nat.choose (Fintype.card Position) queryCount)) =
        ((Fintype.card (Fin count → Row → F) : Rat) *
          ((Nat.choose (threshold - 1) queryCount : Rat) * Fintype.card (Row → F) +
            count * (universalLineBudget (Row := Row) point degree threshold queryCount : Rat))) /
          Fintype.card (Row → F) := by
    field_simp [coefficientPositive.ne', samplePositive.ne']
  rw [identity]
  exact (le_div_iff₀ coefficientPositive).2 boundRat

end ExactQueryExperiment

abbrev Smz9Position := Fin V8Smz9DisjointCoset.domainSize
abbrev Smz9Coefficients := Fin 140 → Fin 5 → Goldilocks

/-- Unnormalized current-profile constant. The claim that its normalized value is at most
2^52 is an outstanding finite inequality, not a theorem or premise hidden in this definition. -/
def smz9LineBudget : ℕ :=
  universalLineBudget (Row := Fin 5) V8Smz9DisjointCoset.evaluationPoint 387 416 20

/-- The literal current coset, 140 independent five-word columns and fresh exact twenty-subset.
This bound is unconditional but not a numerical security certificate. -/
theorem smz9_arbitrary_source_recovery_probability_le
    (data : ℕ → Smz9Position → Goldilocks) (masks : Fin 5 → Smz9Position → Goldilocks)
    (response : Smz9Coefficients → BoundedResponse Goldilocks (Fin 5) 387) :
    V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability
        (unrecoveredQueryEvent V8Smz9DisjointCoset.evaluationPoint 387 20
          data masks response) ≤
      (Nat.choose 415 20 : Rat) / Nat.choose (2 ^ 23) 20 +
        140 * (smz9LineBudget : Rat) /
          ((goldilocksModulus : Rat) ^ 5 * Nat.choose (2 ^ 23) 20) := by
  have coefficientCard : Fintype.card (Fin 5 → Goldilocks) = goldilocksModulus ^ 5 := by
    rw [Fintype.card_fun, Fintype.card_fin, goldilocks_card]
  have sampleFits : 20 ≤ Fintype.card Smz9Position := by
    rw [Fintype.card_fin]
    decide
  have bound := arbitrary_source_recovery_probability_le
    V8Smz9DisjointCoset.evaluationPoint 387 416 20 (by decide) sampleFits data masks response
  rw [coefficientCard, Fintype.card_fin, Nat.cast_pow] at bound
  exact bound

end

end HegemonCrypto.SmallWood.V8Smz9McaRecovery
