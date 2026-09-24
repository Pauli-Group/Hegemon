import Mca38UniversalBadLineCount
import SmzaQ38McaSourceBindingR2
import HegemonCrypto.CmsClassicalDatabase
import HegemonCrypto.UniformSubsetSampling

/-!
# The two actual MCA role events

The exceptional matrix quantifies over EVERY subsequent bounded response.
Its label is only the committed oracle, fixed before the DECS matrix. Outside
that event, a failed decoder can accept only a q38 subset of a fixed support
of size below65536. Thus the matrix and final-query roles have separate local
densities; there is no independence assumption on the adversarial response.
The universal line-count theorem is applied, not supplied as a premise.
-/
namespace HegemonCrypto.SmallWood.SmzaRp04McaRoleCells

open scoped BigOperators Classical
open SmzaQ38OracleExtraction SmzaQ38McaSourceBinding
open V8Smz9McaRecovery V8Smz9McaDecoder
open Mca38UniversalMatrixEvent Mca38UniversalBadLineCount
open HegemonCrypto.CmsClassicalDatabase

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option diagnostics true
set_option exponentiation.threshold 1024
set_option backward.isDefEq.respectTransparency true
attribute [local irreducible] oracleData oracleMasks V8Smz9DisjointCoset.evaluationPoint

def matrixBad (oracle : CommittedOracle) (coefficients : Coefficients) : Prop :=
  BadMatrix smz9EvaluationPoint 405 65536 (oracleData oracle) (oracleMasks oracle) coefficients

def matrixLoss : Rat :=
  (140 * 12310499043179 : Rat) / Fintype.card (Fin 5 → Goldilocks)

theorem matrix_bad_card_bound (oracle : CommittedOracle) :
    (badMatrices smz9EvaluationPoint 405 65536
      (oracleData oracle) (oracleMasks oracle) 140).card *
        Fintype.card (Fin 5 → Goldilocks) ≤
      Fintype.card Coefficients * (140 * 12310499043179) := by
  have lines : ∀ (column : Fin 140) (prior : Fin 5 → Position → Goldilocks),
      (badLineLabels smz9EvaluationPoint 405 65536 prior
        (oracleData oracle column.val)).card ≤ 12310499043179 :=
    fun column prior => universal_badLineLabels_65536 prior (oracleData oracle column.val)
  have bound := universal_bad_matrix_card_bound (F := Goldilocks) (Row := Fin 5)
    smz9EvaluationPoint 405 65536 (oracleData oracle) (oracleMasks oracle)
    140 12310499043179
    lines
  simpa only [Coefficients, Fintype.card_fun, Fintype.card_fin] using bound

theorem output_density_of_card_bound {A B : Type*} [Fintype A] [Fintype B]
    [Nonempty A] [Nonempty B] (event : A → Prop) (budget : Nat)
    (bound : (Finset.univ.filter event).card * Fintype.card B ≤
      Fintype.card A * budget) :
    outputEventProbability event ≤ (budget : Rat) / Fintype.card B := by
  classical
  have aPositive : (0 : Rat) < Fintype.card A := by exact_mod_cast Fintype.card_pos
  have bPositive : (0 : Rat) < Fintype.card B := by exact_mod_cast Fintype.card_pos
  unfold outputEventProbability
  apply (div_le_div_iff₀ aPositive bPositive).2
  exact_mod_cast (by simpa only [Nat.mul_comm] using bound :
    (Finset.univ.filter event).card * Fintype.card B ≤ budget * Fintype.card A)

theorem matrix_bad_output_density (oracle : CommittedOracle) :
    outputEventProbability (matrixBad oracle) ≤ matrixLoss := by
  classical
  have sameSet : (Finset.univ.filter (matrixBad oracle)) =
      badMatrices smz9EvaluationPoint 405 65536
        (oracleData oracle) (oracleMasks oracle) 140 := by
    ext coefficients
    simp only [matrixBad, badMatrices, Finset.mem_filter, Finset.mem_univ, true_and]
  have bound : (Finset.univ.filter (matrixBad oracle)).card *
      Fintype.card (Fin 5 → Goldilocks) ≤ Fintype.card Coefficients *
      (140 * 12310499043179) := by
    rw [sameSet]
    exact matrix_bad_card_bound oracle
  have density := output_density_of_card_bound (B := Fin 5 → Goldilocks)
    (matrixBad oracle) (140 * 12310499043179) bound
  simpa only [matrixLoss, Nat.cast_mul, Nat.cast_ofNat] using density

structure SmallSupportLabel where
  support : Finset Position
  small : support.card < 65536

def smallSupportBad (label : SmallSupportLabel) (query : Query) : Prop :=
  query.val ⊆ label.support

def smallSupportLoss : Rat :=
  (Nat.choose 65535 38 : Rat) / Nat.choose (Fintype.card Position) 38

theorem small_support_output_density (label : SmallSupportLabel) :
    outputEventProbability (smallSupportBad label) ≤ smallSupportLoss := by
  classical
  have samples : (Finset.univ.filter (smallSupportBad label)) =
      sampleWithinEvent label.support 38 := by
    ext query
    simp only [smallSupportBad, sampleWithinEvent, Finset.mem_filter,
      Finset.mem_univ, true_and]
  have cardinal : (Finset.univ.filter (smallSupportBad label)).card ≤
      Nat.choose 65535 38 := by
    rw [samples, sample_within_event_card]
    exact Nat.choose_le_choose 38 (by have small := label.small; omega)
  unfold outputEventProbability smallSupportLoss
  rw [query_sample_card]
  exact div_le_div_of_nonneg_right (by exact_mod_cast cardinal) (Nat.cast_nonneg _)

theorem accepted_decoder_failure_is_matrix_or_query_cell
    (oracle : CommittedOracle) (response : ResponseStrategy)
    (coefficients : Coefficients) (query : Query)
    (failed : DecoderFailure oracle response coefficients query) :
    matrixBad oracle coefficients ∨
      ∃ label : SmallSupportLabel,
        label.support = agreementSupport oracle response coefficients ∧
          smallSupportBad label query := by
  classical
  have genericFailure : query ∈ decoderFailureEvent smz9EvaluationPoint 405 38
      (oracleData oracle) (oracleMasks oracle) response coefficients := by
    apply Finset.mem_filter.mpr
    refine ⟨Finset.mem_univ _, ?_, failed.2⟩
    exact (query_accepts_iff_prequery_agreement oracle response coefficients query).mp failed.1
  obtain bad | small := accepted_decoder_failure_implies_bad_matrix_or_small_support
    smz9EvaluationPoint smz9_evaluation_point_injective 405 65536 38 (by decide)
    (oracleData oracle) (oracleMasks oracle) response coefficients query genericFailure
  · exact Or.inl bad
  · right
    exact ⟨⟨agreementSupport oracle response coefficients, small.1⟩, rfl, small.2⟩

end
end HegemonCrypto.SmallWood.SmzaRp04McaRoleCells
