import HegemonCrypto.SmallWoodDecsRestore
import HegemonCrypto.UniformSubsetSampling

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Exact SmallWood LVCS opening transition

The fourth SmallWood error term is not a claim that random sampling detects an arbitrary bad
word. It applies after DECS extraction has fixed degree-126 row polynomials. A false LVCS
opening then creates a nonzero degree-126 discrepancy polynomial, so all 20 sampled DECS
positions can pass only when they are roots of that polynomial.

This module proves that exact implication and the resulting hypergeometric bound.  It also models
the production Rust layout: a combination message is transmitted as 107 data values followed by
20 hiding values, then rotated to `[hiding | data]` before interpolation at `0 .. 126`.
-/

namespace HegemonCrypto.SmallWood.LvcsOpening

open Polynomial
open scoped BigOperators
open HegemonCrypto.FiniteFieldSampling
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.UniformSubsetSampling
open Hegemon.Transaction.SmallWoodNoGrindingSoundness
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open Hegemon.Transaction.SmallWoodTranscriptBinding

noncomputable section

/-- Consecutive field point used by Rust's LVCS interpolation after left rotation. -/
def lvcsInterpolationPoint
    (index : Fin (lvcsColumnCount + decsOpenedEvaluations)) : Goldilocks :=
  toGoldilocks index.val

theorem lvcs_interpolation_point_injective :
    Function.Injective lvcsInterpolationPoint := by
  intro left right equality
  have naturalEquality := congrArg fromGoldilocks equality
  change
    fromGoldilocks (toGoldilocks left.val) =
      fromGoldilocks (toGoldilocks right.val) at naturalEquality
  rw [fromGoldilocks_toGoldilocks, fromGoldilocks_toGoldilocks] at naturalEquality
  have leftBound : left.val < goldilocksModulus := by
    have := left.isLt
    change left.val < 127 at this
    exact this.trans (by decide)
  have rightBound : right.val < goldilocksModulus := by
    have := right.isLt
    change right.val < 127 at this
    exact this.trans (by decide)
  simp [fieldValue, Nat.mod_eq_of_lt leftBound,
    Nat.mod_eq_of_lt rightBound] at naturalEquality
  exact Fin.ext naturalEquality

/--
Value at one post-rotation interpolation point. The wire message is `[107 data | 20 hiding]`;
Rust rotates it to `[20 hiding | 107 data]`.
-/
def rotatedCombinationValue
    (message : PcsCombinationMessage)
    (combination : Fin openedCombinationCount)
    (index : Fin (lvcsColumnCount + decsOpenedEvaluations)) : Goldilocks :=
  if isHiding : index.val < decsOpenedEvaluations then
    wordToGoldilocks
      (message combination
        ⟨lvcsColumnCount + index.val, by
          have indexBound := index.isLt
          change index.val < 127 at indexBound
          change 107 + index.val < 127
          change index.val < 20 at isHiding
          omega⟩)
  else
    wordToGoldilocks
      (message combination
        ⟨index.val - decsOpenedEvaluations, by
          have indexBound := index.isLt
          change index.val < 127 at indexBound
          change index.val - 20 < 127
          omega⟩)

/-- Exact polynomial reconstructed from one production LVCS combination message. -/
def claimedCombinationPolynomial
    (message : PcsCombinationMessage)
    (combination : Fin openedCombinationCount) : Goldilocks[X] :=
  Lagrange.interpolate
    (Finset.univ :
      Finset (Fin (lvcsColumnCount + decsOpenedEvaluations)))
    lvcsInterpolationPoint
    (rotatedCombinationValue message combination)

theorem claimed_combination_polynomial_degree_le
    (message : PcsCombinationMessage)
    (combination : Fin openedCombinationCount) :
    (claimedCombinationPolynomial message combination).natDegree ≤
      decsPolynomialDegree := by
  apply natDegree_le_iff_coeff_eq_zero.mpr
  intro degree aboveBound
  have interpolationDegree :
      (claimedCombinationPolynomial message combination).degree <
        (Finset.univ :
          Finset (Fin (lvcsColumnCount + decsOpenedEvaluations))).card := by
    exact Lagrange.degree_interpolate_lt _
      lvcs_interpolation_point_injective.injOn
  have interpolationCard :
      (Finset.univ :
        Finset (Fin (lvcsColumnCount + decsOpenedEvaluations))).card = 127 := by
    decide
  rw [interpolationCard] at interpolationDegree
  have indexAtLeast : 127 ≤ degree := by
    change 126 < degree at aboveBound
    omega
  exact coeff_eq_zero_of_degree_lt
    (interpolationDegree.trans_le (by exact_mod_cast indexAtLeast))

/-- Polynomial fixed by a linear combination of the degree-bounded committed LVCS rows. -/
def committedCombinationPolynomial
    (oracle : CommittedOracle)
    (coefficient : Fin lvcsRowCount -> Goldilocks) : Goldilocks[X] :=
  ∑ row : Fin lvcsRowCount,
    C (coefficient row) * interpolatedCommittedRow oracle row

theorem committed_combination_polynomial_degree_le
    (oracle : CommittedOracle)
    (degreeBounded : CommittedRowsDegreeBounded oracle)
    (coefficient : Fin lvcsRowCount -> Goldilocks) :
    (committedCombinationPolynomial oracle coefficient).natDegree ≤
      decsPolynomialDegree := by
  unfold committedCombinationPolynomial
  apply natDegree_sum_le_of_forall_le
  intro row _
  exact
    (natDegree_C_mul_le _ _).trans
      (interpolated_committed_row_degree_le oracle degreeBounded row)

/-- Opening-point index `j` in Rust's combination ordering `j * beta + block`. -/
def combinationOpeningIndex
    (combination : Fin openedCombinationCount) : Fin openedEvaluations :=
  ⟨combination.val / beta, by
    have combinationBound := combination.isLt
    change combination.val < 35 at combinationBound
    change combination.val / 7 < 5
    omega⟩

/-- Stacking block `k` in Rust's combination ordering `j * beta + k`. -/
def combinationBlockIndex
    (combination : Fin openedCombinationCount) : Fin beta :=
  ⟨combination.val % beta, Nat.mod_lt _ (by decide)⟩

/-- Two-way stacking block containing one LVCS row. -/
def lvcsRowBlockIndex (row : Fin lvcsRowCount) : Fin beta :=
  ⟨row.val / unstackedRowCount, by
    have rowBound := row.isLt
    change row.val < 483 at rowBound
    change row.val / 69 < 7
    omega⟩

/-- Exponent inside the selected 69-row stacking block. -/
def lvcsRowExponent (row : Fin lvcsRowCount) : Fin unstackedRowCount :=
  ⟨row.val % unstackedRowCount, Nat.mod_lt _ (by decide)⟩

/--
Exact coefficient written by `pcs_build_coefficients`: combination `j * 7 + k` contains
`1, r_j, ..., r_j^68` on block `k` and zero on every other block.
-/
def productionCombinationCoefficient
    (opening : PiopOpeningChallenge)
    (combination : Fin openedCombinationCount)
    (row : Fin lvcsRowCount) : Goldilocks :=
  if lvcsRowBlockIndex row = combinationBlockIndex combination then
    wordToGoldilocks (opening.val (combinationOpeningIndex combination)) ^
      (lvcsRowExponent row).val
  else
    0

theorem production_combination_coefficient_selected_block
    (opening : PiopOpeningChallenge)
    (combination : Fin openedCombinationCount)
    (row : Fin lvcsRowCount)
    (selected :
      lvcsRowBlockIndex row = combinationBlockIndex combination) :
    productionCombinationCoefficient opening combination row =
      wordToGoldilocks (opening.val (combinationOpeningIndex combination)) ^
        (lvcsRowExponent row).val := by
  simp [productionCombinationCoefficient, selected]

theorem production_combination_coefficient_other_block
    (opening : PiopOpeningChallenge)
    (combination : Fin openedCombinationCount)
    (row : Fin lvcsRowCount)
    (other :
      lvcsRowBlockIndex row ≠ combinationBlockIndex combination) :
    productionCombinationCoefficient opening combination row = 0 := by
  simp [productionCombinationCoefficient, other]

/-- Exact production combination index `j * 7 + k`. -/
def productionCombinationIndex
    (openingIndex : Fin openedEvaluations)
    (block : Fin beta) : Fin openedCombinationCount :=
  ⟨openingIndex.val * beta + block.val, by
    have openingBound := openingIndex.isLt
    have blockBound := block.isLt
    change openingIndex.val < 5 at openingBound
    change block.val < 7 at blockBound
    change openingIndex.val * 7 + block.val < 35
    omega⟩

theorem combination_opening_index_production_combination_index
    (openingIndex : Fin openedEvaluations)
    (block : Fin beta) :
    combinationOpeningIndex (productionCombinationIndex openingIndex block) =
      openingIndex := by
  apply Fin.ext
  simp [combinationOpeningIndex, productionCombinationIndex, beta]
  omega

theorem combination_block_index_production_combination_index
    (openingIndex : Fin openedEvaluations)
    (block : Fin beta) :
    combinationBlockIndex (productionCombinationIndex openingIndex block) =
      block := by
  apply Fin.ext
  have blockBound := block.isLt
  change block.val < 7 at blockBound
  simp [combinationBlockIndex, productionCombinationIndex, beta]

/--
The 35 rows omitted from the final wire opening are the first five rows in each
of the seven stacking blocks, in the exact order used by Rust's `fullrank_cols`.
-/
def selectedLvcsRow
    (block : Fin beta)
    (exponent : Fin openedEvaluations) : Fin lvcsRowCount :=
  ⟨block.val * unstackedRowCount + exponent.val, by
    have blockBound := block.isLt
    have exponentBound := exponent.isLt
    change block.val < 7 at blockBound
    change exponent.val < 5 at exponentBound
    change block.val * 69 + exponent.val < 483
    omega⟩

theorem lvcs_row_block_index_selected_lvcs_row
    (block : Fin beta)
    (exponent : Fin openedEvaluations) :
    lvcsRowBlockIndex (selectedLvcsRow block exponent) = block := by
  apply Fin.ext
  have blockBound := block.isLt
  have exponentBound := exponent.isLt
  change block.val < 7 at blockBound
  change exponent.val < 5 at exponentBound
  change (block.val * 69 + exponent.val) / 69 = block.val
  omega

theorem lvcs_row_exponent_selected_lvcs_row
    (block : Fin beta)
    (exponent : Fin openedEvaluations) :
    (lvcsRowExponent (selectedLvcsRow block exponent)).val = exponent.val := by
  have exponentBound := exponent.isLt
  change exponent.val < 5 at exponentBound
  change (block.val * 69 + exponent.val) % 69 = exponent.val
  omega

/-- The five distinct PIOP opening points, embedded in the Goldilocks field. -/
def openingEvaluationPoint
    (opening : PiopOpeningChallenge)
    (openingIndex : Fin openedEvaluations) : Goldilocks :=
  wordToGoldilocks (opening.val openingIndex)

theorem opening_evaluation_point_injective
    (opening : PiopOpeningChallenge) :
    Function.Injective (openingEvaluationPoint opening) := by
  exact fieldWordGoldilocksEquiv.injective.comp opening.property.1

/--
On one selected row, the production coefficient matrix is exactly the
Vandermonde entry `r_j ^ exponent`.
-/
theorem production_combination_coefficient_selected_row
    (opening : PiopOpeningChallenge)
    (openingIndex : Fin openedEvaluations)
    (block : Fin beta)
    (exponent : Fin openedEvaluations) :
    productionCombinationCoefficient opening
        (productionCombinationIndex openingIndex block)
        (selectedLvcsRow block exponent) =
      openingEvaluationPoint opening openingIndex ^ exponent.val := by
  rw [production_combination_coefficient_selected_block]
  · rw [combination_opening_index_production_combination_index,
      lvcs_row_exponent_selected_lvcs_row]
    rfl
  · rw [lvcs_row_block_index_selected_lvcs_row,
      combination_block_index_production_combination_index]

/--
The 35 omitted LVCS evaluations are uniquely determined by the 35 production
combination equations once the other 448 evaluations are known. Algebraically
this is seven independent 5-by-5 Vandermonde systems. This is the exact
full-rank fact relied on by `pcs_reconstruct_combi_heads`.
-/
theorem selected_lvcs_reconstruction_unique
    (opening : PiopOpeningChallenge)
    (left right : Fin beta -> Fin openedEvaluations -> Goldilocks)
    (sameCombinationEquations :
      ∀ openingIndex block,
        (∑ exponent : Fin openedEvaluations,
          productionCombinationCoefficient opening
              (productionCombinationIndex openingIndex block)
              (selectedLvcsRow block exponent) *
            left block exponent) =
        ∑ exponent : Fin openedEvaluations,
          productionCombinationCoefficient opening
              (productionCombinationIndex openingIndex block)
              (selectedLvcsRow block exponent) *
            right block exponent) :
    left = right := by
  funext block exponent
  let difference : Fin openedEvaluations -> Goldilocks :=
    fun index => left block index - right block index
  have equations :
      ∀ openingIndex : Fin openedEvaluations,
        (∑ index : Fin openedEvaluations,
          openingEvaluationPoint opening openingIndex ^ index.val *
            difference index) = 0 := by
    intro openingIndex
    calc
      (∑ index : Fin openedEvaluations,
          openingEvaluationPoint opening openingIndex ^ index.val *
            difference index) =
          (∑ index : Fin openedEvaluations,
              productionCombinationCoefficient opening
                  (productionCombinationIndex openingIndex block)
                  (selectedLvcsRow block index) *
                left block index) -
            ∑ index : Fin openedEvaluations,
              productionCombinationCoefficient opening
                  (productionCombinationIndex openingIndex block)
                  (selectedLvcsRow block index) *
                right block index := by
                  simp_rw [
                    production_combination_coefficient_selected_row,
                    difference, mul_sub, Finset.sum_sub_distrib]
      _ = 0 := sub_eq_zero.mpr
        (sameCombinationEquations openingIndex block)
  have differenceZero : difference = 0 :=
    Matrix.eq_zero_of_forall_index_sum_pow_mul_eq_zero
      (opening_evaluation_point_injective opening) equations
  have entryZero := congrFun differenceZero exponent
  exact sub_eq_zero.mp (by simpa [difference] using entryZero)

/-- Every one of the 35 transmitted combination rows matches its committed LVCS linear form. -/
def ProductionCombinationsMatch
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle) : Prop :=
  ∀ combination : Fin openedCombinationCount,
    claimedCombinationPolynomial message combination =
      committedCombinationPolynomial oracle
        (productionCombinationCoefficient opening combination)

/-- DECS positions at which a polynomial discrepancy vanishes. -/
noncomputable def activeRootIndexSet (polynomial : Goldilocks[X]) :
    Finset (Fin decsEvaluationCount) := by
  classical
  exact Finset.univ.filter fun index =>
    polynomial.eval (activeEvaluationPoint index) = 0

theorem mem_active_root_index_set_iff
    (polynomial : Goldilocks[X])
    (index : Fin decsEvaluationCount) :
    index ∈ activeRootIndexSet polynomial ↔
      polynomial.eval (activeEvaluationPoint index) = 0 := by
  simp [activeRootIndexSet]

/-- Injectivity of the active radix-2 domain transfers the standard polynomial root bound. -/
theorem active_root_index_set_card_le_natDegree
    {polynomial : Goldilocks[X]}
    (nonzero : polynomial ≠ 0) :
    (activeRootIndexSet polynomial).card ≤ polynomial.natDegree := by
  let embedding : Fin decsEvaluationCount ↪ Goldilocks :=
    ⟨activeEvaluationPoint, active_evaluation_point_injective⟩
  have imageSubset :
      (activeRootIndexSet polynomial).map embedding ⊆
        HegemonCrypto.FiniteFieldSampling.rootSet polynomial := by
    intro point pointMembership
    obtain ⟨index, indexMembership, pointEquation⟩ :=
      Finset.mem_map.mp pointMembership
    subst point
    exact (mem_root_set_iff polynomial (activeEvaluationPoint index)).mpr
      ((mem_active_root_index_set_iff polynomial index).mp indexMembership)
  calc
    (activeRootIndexSet polynomial).card =
        ((activeRootIndexSet polynomial).map embedding).card := by
          rw [Finset.card_map]
    _ ≤ (HegemonCrypto.FiniteFieldSampling.rootSet polynomial).card :=
      Finset.card_le_card imageSubset
    _ ≤ polynomial.natDegree :=
      root_set_card_le_nat_degree nonzero

/-- Ideal probability that all 20 uniformly sampled DECS positions hide one discrepancy. -/
noncomputable def discrepancyOpeningFailureProbability
    (polynomial : Goldilocks[X]) : Rat :=
  (Nat.choose (activeRootIndexSet polynomial).card decsOpenedEvaluations : Rat) /
    Nat.choose decsEvaluationCount decsOpenedEvaluations

/--
A nonzero degree-126 discrepancy survives the active 20-position DECS opening with probability at
most the exact fourth SmallWood error term.
-/
theorem discrepancy_opening_failure_probability_le_epsilon4
    {polynomial : Goldilocks[X]}
    (nonzero : polynomial ≠ 0)
    (degreeBounded : polynomial.natDegree ≤ decsPolynomialDegree) :
    discrepancyOpeningFailureProbability polynomial ≤
      (Nat.choose decsPolynomialDegree decsOpenedEvaluations : Rat) /
        Nat.choose decsEvaluationCount decsOpenedEvaluations := by
  have rootCardBound :
      (activeRootIndexSet polynomial).card ≤ decsPolynomialDegree :=
    (active_root_index_set_card_le_natDegree nonzero).trans degreeBounded
  unfold discrepancyOpeningFailureProbability
  have denominatorPositive :
      (0 : Rat) < Nat.choose decsEvaluationCount decsOpenedEvaluations := by
    exact_mod_cast Nat.choose_pos (by decide)
  apply (div_le_div_iff_of_pos_right denominatorPositive).2
  exact_mod_cast Nat.choose_le_choose decsOpenedEvaluations rootCardBound

/--
The exact LVCS fourth-round reduction: once DECS has extracted degree-bounded committed rows, a
false claimed combination can pass the sampled openings only within `epsilon4`.
-/
theorem false_combination_opening_probability_le_epsilon4
    (message : PcsCombinationMessage)
    (combination : Fin openedCombinationCount)
    (oracle : CommittedOracle)
    (degreeBounded : CommittedRowsDegreeBounded oracle)
    (coefficient : Fin lvcsRowCount -> Goldilocks)
    (falseClaim :
      claimedCombinationPolynomial message combination ≠
        committedCombinationPolynomial oracle coefficient) :
    discrepancyOpeningFailureProbability
        (claimedCombinationPolynomial message combination -
          committedCombinationPolynomial oracle coefficient) ≤
      (Nat.choose decsPolynomialDegree decsOpenedEvaluations : Rat) /
        Nat.choose decsEvaluationCount decsOpenedEvaluations := by
  apply discrepancy_opening_failure_probability_le_epsilon4
  · exact sub_ne_zero.mpr falseClaim
  · simpa using natDegree_sub_le_of_le
      (claimed_combination_polynomial_degree_le message combination)
      (committed_combination_polynomial_degree_le
        oracle degreeBounded coefficient)

/-- Exact active LVCS specialization of the fourth-round discrepancy bound. -/
theorem false_production_combination_opening_probability_le_epsilon4
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (combination : Fin openedCombinationCount)
    (oracle : CommittedOracle)
    (degreeBounded : CommittedRowsDegreeBounded oracle)
    (falseClaim :
      claimedCombinationPolynomial message combination ≠
        committedCombinationPolynomial oracle
          (productionCombinationCoefficient opening combination)) :
    discrepancyOpeningFailureProbability
        (claimedCombinationPolynomial message combination -
          committedCombinationPolynomial oracle
            (productionCombinationCoefficient opening combination)) ≤
      (Nat.choose decsPolynomialDegree decsOpenedEvaluations : Rat) /
        Nat.choose decsEvaluationCount decsOpenedEvaluations := by
  exact false_combination_opening_probability_le_epsilon4
    message combination oracle degreeBounded
    (productionCombinationCoefficient opening combination)
    falseClaim

/-- Pointwise equality checked after LVCS row reconstruction. -/
def ProductionCombinationPassesAt
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (combination : Fin openedCombinationCount)
    (oracle : CommittedOracle)
    (index : Fin decsEvaluationCount) : Prop :=
  (claimedCombinationPolynomial message combination).eval
      (activeEvaluationPoint index) =
    (committedCombinationPolynomial oracle
      (productionCombinationCoefficient opening combination)).eval
        (activeEvaluationPoint index)

theorem production_combination_passes_at_iff_discrepancy_root
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (combination : Fin openedCombinationCount)
    (oracle : CommittedOracle)
    (index : Fin decsEvaluationCount) :
    ProductionCombinationPassesAt opening message combination oracle index ↔
      index ∈ activeRootIndexSet
        (claimedCombinationPolynomial message combination -
          committedCombinationPolynomial oracle
            (productionCombinationCoefficient opening combination)) := by
  rw [mem_active_root_index_set_iff]
  simp only [ProductionCombinationPassesAt, eval_sub, sub_eq_zero]

/-- All checks for one claimed combination at one fixed 20-position challenge. -/
def ProductionCombinationPassesOn
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (combination : Fin openedCombinationCount)
    (oracle : CommittedOracle)
    (challenge : DecsOpeningChallenge) : Prop :=
  ∀ index ∈ challenge.val,
    ProductionCombinationPassesAt opening message combination oracle index

theorem production_combination_passes_on_iff_subset_roots
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (combination : Fin openedCombinationCount)
    (oracle : CommittedOracle)
    (challenge : DecsOpeningChallenge) :
    ProductionCombinationPassesOn opening message combination oracle challenge ↔
      challenge.val ⊆
        activeRootIndexSet
          (claimedCombinationPolynomial message combination -
            committedCombinationPolynomial oracle
              (productionCombinationCoefficient opening combination)) := by
  constructor
  · intro passes index membership
    exact
      (production_combination_passes_at_iff_discrepancy_root
        opening message combination oracle index).mp
        (passes index membership)
  · intro subset index membership
    exact
        (production_combination_passes_at_iff_discrepancy_root
          opening message combination oracle index).mpr
        (subset membership)

/-- The production DECS challenge type is exactly the fixed-cardinality subset sample space. -/
def decsOpeningChallengeEquivSampleSpace :
    DecsOpeningChallenge ≃
      { sample : Finset (Fin decsEvaluationCount) //
        sample ∈
          sampleSpace
            (Finset.univ : Finset (Fin decsEvaluationCount))
            decsOpenedEvaluations } where
  toFun challenge :=
    ⟨challenge.val, Finset.mem_powersetCard.mpr
      ⟨Finset.subset_univ _, challenge.property⟩⟩
  invFun sample :=
    ⟨sample.val, (Finset.mem_powersetCard.mp sample.property).2⟩
  left_inv challenge := by
    apply Subtype.ext
    rfl
  right_inv sample := by
    apply Subtype.ext
    rfl

/--
Passing challenges for one production combination are exactly the fixed-size
subsets of that combination's discrepancy roots.
-/
def passingProductionCombinationEquivBadSamples
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (combination : Fin openedCombinationCount)
    (oracle : CommittedOracle) :
    { challenge : DecsOpeningChallenge //
      ProductionCombinationPassesOn
        opening message combination oracle challenge } ≃
      { sample : Finset (Fin decsEvaluationCount) //
        sample ∈
          badSamples
            (Finset.univ : Finset (Fin decsEvaluationCount))
            (activeRootIndexSet
              (claimedCombinationPolynomial message combination -
                committedCombinationPolynomial oracle
                  (productionCombinationCoefficient opening combination)))
            decsOpenedEvaluations } where
  toFun challenge := by
    refine ⟨challenge.val.val, ?_⟩
    apply Finset.mem_filter.mpr
    constructor
    · exact Finset.mem_powersetCard.mpr
        ⟨Finset.subset_univ _, challenge.val.property⟩
    · exact
        (production_combination_passes_on_iff_subset_roots
          opening message combination oracle challenge.val).mp
          challenge.property
  invFun sample := by
    have sampleFacts := Finset.mem_filter.mp sample.property
    let challenge : DecsOpeningChallenge :=
      ⟨sample.val, (Finset.mem_powersetCard.mp sampleFacts.1).2⟩
    refine ⟨challenge, ?_⟩
    exact
      (production_combination_passes_on_iff_subset_roots
        opening message combination oracle challenge).mpr sampleFacts.2
  left_inv challenge := by
    apply Subtype.ext
    apply Subtype.ext
    rfl
  right_inv sample := by
    apply Subtype.ext
    rfl

/--
The finite uniform challenge semantics and the exact combinatorial discrepancy
probability are the same object.
-/
theorem production_combination_opening_uniform_probability_eq
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (combination : Fin openedCombinationCount)
    (oracle : CommittedOracle) :
    uniformEventProbability
        (ProductionCombinationPassesOn
          opening message combination oracle) =
      discrepancyOpeningFailureProbability
        (claimedCombinationPolynomial message combination -
          committedCombinationPolynomial oracle
            (productionCombinationCoefficient opening combination)) := by
  classical
  let roots :=
    activeRootIndexSet
      (claimedCombinationPolynomial message combination -
        committedCombinationPolynomial oracle
          (productionCombinationCoefficient opening combination))
  have numerator :
      (uniformEventSet
        (ProductionCombinationPassesOn
          opening message combination oracle)).card =
        (badSamples
          (Finset.univ : Finset (Fin decsEvaluationCount))
          roots decsOpenedEvaluations).card := by
    unfold uniformEventSet
    rw [← Fintype.card_subtype]
    rw [← Fintype.card_coe]
    exact Fintype.card_congr
      (passingProductionCombinationEquivBadSamples
        opening message combination oracle)
  have denominator :
      Fintype.card DecsOpeningChallenge =
        (sampleSpace
          (Finset.univ : Finset (Fin decsEvaluationCount))
          decsOpenedEvaluations).card := by
    rw [← Fintype.card_coe]
    exact Fintype.card_congr decsOpeningChallengeEquivSampleSpace
  unfold uniformEventProbability discrepancyOpeningFailureProbability
  rw [numerator, denominator]
  rw [bad_samples_card (Finset.subset_univ roots), sample_space_card]
  simp only [Finset.card_univ, Fintype.card_fin]
  rfl

end

end HegemonCrypto.SmallWood.LvcsOpening
