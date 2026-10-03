import SmzaRp04ChronologicalAlgebra
import SmzaRp05Q38CurrentRebinding
import SmzaRp05AcceptedQ38AgreementBridge
import HegemonCrypto.UniformSubsetSampling

/-!
# Current-map q38 discrepancy detection bound

For a fixed nonzero LVCS discrepancy of degree at most 405, the current RP05
evaluation map has at most 405 zero indices. A uniform 38-subset of the same
DECS index type therefore misses the discrepancy with probability at most the
existing q38 root-count expression. This is a finite uniform-subset result;
it does not identify the law of an adaptive or quantum oracle sampler.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentQ38DetectionProbability

open Polynomial
open SmzaRp04ChronologicalAlgebra
open SmzaQ38Recovery SmzaQ38OracleExtraction
open SmzaQ38McaSourceBinding
open V8Smz9RobustQueryMismatch
open HegemonCrypto.SmallWood.V8Smz9McaRecovery
open HegemonCrypto.SmallWood.SmzaRp05Q38CurrentRebinding
open HegemonCrypto.SmallWood.SmzaRp05AcceptedQ38AgreementBridge

noncomputable section
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

/-- Indices where the fixed discrepancy vanishes under the current RP05 map. -/
def currentRootIndices (polynomial : Goldilocks[X]) :
    Finset (Fin SmzaRp05Q38CurrentRebinding.decsDomainSize) :=
  Finset.univ.filter fun index =>
    polynomial.eval (SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint index) = 0

private theorem mem_current_sample_within_event_iff
    {Position : Type*} [Fintype Position]
    (support : Finset Position) (queryCount : Nat)
    (sample : QuerySample Position queryCount) :
    sample ∈ sampleWithinEvent support queryCount ↔ sample.val ⊆ support := by
  classical
  simp only [sampleWithinEvent, Finset.mem_filter, Finset.mem_univ, true_and]

theorem current_root_indices_card_le
    {polynomial : Goldilocks[X]} (nonzero : polynomial ≠ 0) :
    (currentRootIndices polynomial).card ≤ polynomial.natDegree := by
  let embedding :
      { index // index ∈ currentRootIndices polynomial } ↪
        { point // point ∈ FiniteFieldSampling.rootSet polynomial } :=
    { toFun := fun index =>
        ⟨SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint index.val,
          (FiniteFieldSampling.mem_root_set_iff polynomial _).mpr
            ((Finset.mem_filter.mp index.property).2)⟩
      inj' := by
        intro left right same
        apply Subtype.ext
        exact smz9_evaluation_point_injective
          (congrArg
            (fun point : { point // point ∈ FiniteFieldSampling.rootSet polynomial } =>
              point.val)
            same) }
  have count : (currentRootIndices polynomial).card ≤
      (FiniteFieldSampling.rootSet polynomial).card := by
    simpa only [Fintype.card_coe] using Fintype.card_le_of_embedding embedding
  exact count.trans (FiniteFieldSampling.root_set_card_le_nat_degree nonzero)

/-- The current-map event that all 38 sampled positions hide one discrepancy. -/
def currentCombinationBadQueries (rows : RecoveredRows)
    (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials)
    (combination : SmzaQ38LvcsOpening.Combination) : Finset Query :=
  let polynomial := SmzaQ38LvcsOpening.discrepancy rows points claimed combination
  if polynomial = 0 then ∅ else sampleWithinEvent (currentRootIndices polynomial) 38

theorem current_combination_bad_query_probability_le
    (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials)
    (rowsDegree : ∀ row, (rows row).natDegree ≤ 405)
    (claimedDegree : ∀ combination, (claimed combination).natDegree ≤ 405)
    (combination : SmzaQ38LvcsOpening.Combination) :
    FiniteEvents.probability
      (currentCombinationBadQueries rows points claimed combination) ≤
      q38SingleRootLoss := by
  classical
  let polynomial :=
    SmzaQ38LvcsOpening.discrepancy rows points claimed combination
  by_cases zero : polynomial = 0
  · rw [show currentCombinationBadQueries rows points claimed combination = ∅ by
        simp [currentCombinationBadQueries, polynomial, zero],
      FiniteEvents.probability_empty]
    unfold q38SingleRootLoss
    positivity
  · have degree : polynomial.natDegree ≤ 405 := by
      simpa only [polynomial] using
        SmzaQ38LvcsOpening.discrepancy_degree405 rows points claimed
          rowsDegree claimedDegree combination
    have supportCard : (currentRootIndices polynomial).card ≤ 405 :=
      (current_root_indices_card_le zero).trans degree
    have denominatorPositive :
        (0 : Rat) < Nat.choose
          (Fintype.card SmzaQ38McaSourceBinding.Position) 38 := by
      exact_mod_cast Nat.choose_pos (by
        rw [Fintype.card_fin]
        decide)
    have event : currentCombinationBadQueries rows points claimed combination =
        sampleWithinEvent (currentRootIndices polynomial) 38 := by
      simp [currentCombinationBadQueries, polynomial, zero]
    have eventCard :
        (currentCombinationBadQueries rows points claimed combination).card =
          Nat.choose (currentRootIndices polynomial).card 38 := by
      rw [event]
      exact sample_within_event_card _ 38
    have queryCard : Fintype.card Query =
        Nat.choose (Fintype.card SmzaQ38McaSourceBinding.Position) 38 :=
      query_sample_card (Position := SmzaQ38McaSourceBinding.Position) 38
    unfold FiniteEvents.probability q38SingleRootLoss
    rw [eventCard, queryCard]
    apply (div_le_div_iff_of_pos_right denominatorPositive).2
    exact_mod_cast Nat.choose_le_choose 38 supportCard

/-- Failure to detect a fixed nonzero current-map discrepancy puts the query
inside its 38-root event. -/
theorem current_not_detected_mem_bad_event
    (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials)
    (combination : SmzaQ38LvcsOpening.Combination)
    (query : Query)
    (nonzero :
      SmzaQ38LvcsOpening.discrepancy rows points claimed combination ≠ 0)
    (notDetected : ¬ ∃ index ∈ query.val,
      (SmzaQ38LvcsOpening.discrepancy rows points claimed combination).eval
        (SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint index) ≠ 0) :
    query ∈ currentCombinationBadQueries rows points claimed combination := by
  classical
  have allRoots : ∀ index ∈ query.val,
      (SmzaQ38LvcsOpening.discrepancy rows points claimed combination).eval
        (SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint index) = 0 := by
    intro index membership
    by_contra mismatch
    exact notDetected ⟨index, membership, mismatch⟩
  simp only [currentCombinationBadQueries, if_neg nonzero]
  exact (mem_current_sample_within_event_iff _ 38 query).2 (by
    intro index membership
    exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, allRoots index membership⟩)

/-- The missed-detection event for one fixed current-map discrepancy has the
same combinatorial q38 loss expression as RP04. -/
theorem current_discrepancy_missed_probability_le
    (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials)
    (rowsDegree : ∀ row, (rows row).natDegree ≤ 405)
    (claimedDegree : ∀ combination, (claimed combination).natDegree ≤ 405)
    (combination : SmzaQ38LvcsOpening.Combination) :
    FiniteEvents.probability
      (currentCombinationBadQueries rows points claimed combination) ≤
      q38SingleRootLoss :=
  current_combination_bad_query_probability_le rows points claimed rowsDegree
    claimedDegree combination

/-- Union of the twelve fixed current-map LVCS discrepancy miss events. -/
def currentLvcsBadQueryEvent (rows : RecoveredRows)
    (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials) : Finset Query :=
  Finset.univ.biUnion
    (currentCombinationBadQueries rows points claimed)

/-- The twelve-combination current-map union bound, under the same uniform
38-subset experiment as the single-discrepancy theorem. -/
theorem current_lvcs_bad_query_probability_le
    (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials)
    (rowsDegree : ∀ row, (rows row).natDegree ≤ 405)
    (claimedDegree : ∀ combination, (claimed combination).natDegree ≤ 405) :
    FiniteEvents.probability (currentLvcsBadQueryEvent rows points claimed) ≤
      q38LvcsLoss := by
  classical
  unfold currentLvcsBadQueryEvent
  calc
    FiniteEvents.probability
        (Finset.univ.biUnion (currentCombinationBadQueries rows points claimed)) ≤
        (Finset.univ : Finset SmzaQ38LvcsOpening.Combination).card *
          q38SingleRootLoss :=
      FiniteEvents.union_probability_le Finset.univ
        (currentCombinationBadQueries rows points claimed) q38SingleRootLoss
        (fun combination _ => current_combination_bad_query_probability_le
          rows points claimed rowsDegree claimedDegree combination)
    _ = q38LvcsLoss := by
      norm_num [q38LvcsLoss]

/-- Failure of the strict-passing bridge's current-map discrepancy detector
places the query in the 12-combination miss union. This is only an event
inclusion; its probability statement is the separate uniform-subset bound. -/
theorem current_not_detected_mem_lvcs_bad_event
    (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials)
    (query : Query)
    (notDetected :
      ¬ CurrentDiscrepanciesDetected rows points claimed query) :
    query ∈ currentLvcsBadQueryEvent rows points claimed := by
  classical
  unfold CurrentDiscrepanciesDetected at notDetected
  push Not at notDetected
  obtain ⟨combination, nonzero, missed⟩ := notDetected
  have notDetectedCombination : ¬ ∃ index ∈ query.val,
      (SmzaQ38LvcsOpening.discrepancy rows points claimed combination).eval
        (SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint index) ≠ 0 := by
    intro detected
    obtain ⟨index, member, mismatch⟩ := detected
    exact mismatch (missed index member)
  unfold currentLvcsBadQueryEvent
  apply Finset.mem_biUnion.mpr
  refine ⟨combination, Finset.mem_univ _, ?_⟩
  exact current_not_detected_mem_bad_event rows points claimed combination query
    nonzero notDetectedCombination

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentQ38DetectionProbability
