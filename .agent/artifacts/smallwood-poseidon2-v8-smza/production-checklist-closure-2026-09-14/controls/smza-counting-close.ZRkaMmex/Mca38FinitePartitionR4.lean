import Q38DecoderEventR2
import Mathlib.SetTheory.Cardinal.Finite

/-! SCRATCH qualification candidate. Actual support predicates and the finite partition.
No published or geometric count is asserted by this file. -/
namespace HegemonCrypto.SmallWood.Mca38Closure
open V8Smz9McaRecovery Q38DecoderEvent
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

variable {F Position Row : Type*} [Field F] [Fintype F]
  [Fintype Position] [Fintype Row]

/-- Labels with ANY bounded bad full response above cutoff, not a fixed selector. -/
def badSupportLabels (point : Position → F) (degree cutoff : Nat)
    (prior : Row → Position → F) (direction : Position → F) : Finset (Row → F) := by
  classical
  exact Finset.univ.filter fun coefficient =>
    ∃ response : BoundedResponse F Row degree,
      cutoff ≤ (agreement point (lineWord prior direction coefficient)
        (responsePolynomials response)).card ∧
      ¬ CodeOn point degree direction
        (agreement point (lineWord prior direction coefficient) (responsePolynomials response))

theorem arbitrary_bad_support_is_counted (point : Position → F) (degree cutoff : Nat)
    (prior : Row → Position → F) (direction : Position → F) (coefficient : Row → F)
    (support : Finset Position) (large : cutoff ≤ support.card)
    (bad : ¬ CodeOn point degree direction support)
    (combined : VectorCodeOn point degree (lineWord prior direction coefficient) support) :
    coefficient ∈ badSupportLabels point degree cutoff prior direction := by
  classical
  choose response bounded agrees using combined
  have subset : support ⊆ agreement point (lineWord prior direction coefficient) response := by
    intro index member
    exact (mem_agreement point _ response index).mpr (fun row => agrees row index member)
  simp only [badSupportLabels, Finset.mem_filter, Finset.mem_univ, true_and]
  refine ⟨boundedResponseOfPolynomials response bounded, ?_, ?_⟩
  · simpa only [bounded_response_roundtrip] using large.trans (Finset.card_le_card subset)
  · simpa only [bounded_response_roundtrip] using
      (fun h => bad (code_on_mono point degree direction subset h))

theorem counted_label_has_arbitrary_bad_support (point : Position → F) (degree cutoff : Nat)
    (prior : Row → Position → F) (direction : Position → F) (coefficient : Row → F)
    (member : coefficient ∈ badSupportLabels point degree cutoff prior direction) :
    ∃ support : Finset Position, cutoff ≤ support.card ∧
      ¬ CodeOn point degree direction support ∧
      VectorCodeOn point degree (lineWord prior direction coefficient) support := by
  classical
  simp only [badSupportLabels, Finset.mem_filter, Finset.mem_univ, true_and] at member
  obtain ⟨response, large, bad⟩ := member
  refine ⟨_, large, bad, ?_⟩
  intro row
  refine ⟨responsePolynomials response row, bounded_response_degree response row, ?_⟩
  intro index hi
  exact (mem_agreement point _ _ index).mp hi row

theorem coefficient_weight_three_ranges (point : Position → F)
    (degree threshold query low high : Nat) (lowPositive : 0 < low) (highPositive : 0 < high)
    (prior : Row → Position → F) (direction : Position → F) (coefficient : Row → F) :
    badCoefficientWeight point degree threshold query prior direction coefficient ≤
      Nat.choose (low-1) query +
      (if coefficient ∈ badSupportLabels point degree low prior direction
        then Nat.choose (high-1) query else 0) +
      (if coefficient ∈ badSupportLabels point degree high prior direction
        then Nat.choose (Fintype.card Position) query else 0) := by
  classical
  unfold badCoefficientWeight
  apply Finset.sup_le
  intro response _
  let support := agreement point (lineWord prior direction coefficient) (responsePolynomials response)
  change (if threshold ≤ support.card ∧ ¬ CodeOn point degree direction support
    then Nat.choose support.card query else 0) ≤ _
  by_cases bad : threshold ≤ support.card ∧ ¬ CodeOn point degree direction support
  · rw [if_pos bad]
    by_cases isHigh : high ≤ support.card
    · have member : coefficient ∈ badSupportLabels point degree high prior direction := by
        simp only [badSupportLabels, Finset.mem_filter, Finset.mem_univ, true_and]
        exact ⟨response, isHigh, bad.2⟩
      rw [if_pos member]
      have bounded := Nat.choose_le_choose query (Finset.card_le_univ support)
      omega
    · by_cases isLow : low ≤ support.card
      · have member : coefficient ∈ badSupportLabels point degree low prior direction := by
          simp only [badSupportLabels, Finset.mem_filter, Finset.mem_univ, true_and]
          exact ⟨response, isLow, bad.2⟩
        rw [if_pos member]
        have cardBound : support.card ≤ high-1 := by omega
        have bounded := Nat.choose_le_choose query cardBound
        omega
      · have cardBound : support.card ≤ low-1 := by omega
        have bounded := Nat.choose_le_choose query cardBound
        omega
  · rw [if_neg bad]
    exact Nat.zero_le _

theorem line_budget_three_ranges (point : Position → F)
    (degree threshold query low high : Nat) (lowPositive : 0 < low) (highPositive : 0 < high)
    (prior : Row → Position → F) (direction : Position → F) :
    lineCoefficientBudget point degree threshold query prior direction ≤
      Fintype.card (Row → F) * Nat.choose (low-1) query +
      (badSupportLabels point degree low prior direction).card * Nat.choose (high-1) query +
      (badSupportLabels point degree high prior direction).card *
        Nat.choose (Fintype.card Position) query := by
  classical
  have sumIndicator (labels : Finset (Row → F)) (value : Nat) :
      (∑ coefficient : Row → F, if coefficient ∈ labels then value else 0) = labels.card*value := by
    rw [← Finset.sum_filter]
    simp
  unfold lineCoefficientBudget
  calc
    _ ≤ ∑ coefficient : Row → F,
        (Nat.choose (low-1) query +
          (if coefficient ∈ badSupportLabels point degree low prior direction
            then Nat.choose (high-1) query else 0) +
          (if coefficient ∈ badSupportLabels point degree high prior direction
            then Nat.choose (Fintype.card Position) query else 0)) := by
      exact Finset.sum_le_sum (fun coefficient _ =>
        coefficient_weight_three_ranges point degree threshold query low high
          lowPositive highPositive prior direction coefficient)
    _ = _ := by simp only [Finset.sum_add_distrib, sumIndicator, Finset.sum_const,
      Finset.card_univ, smul_eq_mul]

/-- The two premises are geometric support counts, explicitly not their weighted conclusion.
The manuscript supplies the first mathematically; MATHEMATICAL_CLOSURE derives the second.
The cubic-incidence component is separately qualified, but its source support adapter and
published count remain open. This theorem does NOT close UnrestrictedMca38 alone. -/
theorem universal_budget38_of_geometric_counts
    (bchksCount : ∀ (prior : Fin 5 → Position38 → Goldilocks) (direction : Position38 → Goldilocks),
      (badSupportLabels V8Smz9DisjointCoset.evaluationPoint 405 58288 prior direction).card ≤
        19191588994328775603293919496651850544)
    (cubicCount : ∀ (prior : Fin 5 → Position38 → Goldilocks) (direction : Position38 → Goldilocks),
      (badSupportLabels V8Smz9DisjointCoset.evaluationPoint 405 524288 prior direction).card ≤
        42829439649) :
    lineBudget38 ≤ goldilocksModulus^5 * Nat.choose 58287 38 +
      19191588994328775603293919496651850544 * Nat.choose 524287 38 +
      42829439649 * Nat.choose (2^23) 38 := by
  classical
  unfold lineBudget38 universalLineBudget
  apply Finset.sup_le
  intro prior _
  apply Finset.sup_le
  intro direction _
  have partition := line_budget_three_ranges V8Smz9DisjointCoset.evaluationPoint
    405 416 38 58288 524288 (by decide) (by decide) prior direction
  -- Erase the choice of finite enumerations before concrete cardinality rewriting.
  simp only [Fintype.card_eq_nat_card] at partition
  have lowCard : Nat.card (Fin 5 → Goldilocks) = goldilocksModulus^5 := by
    rw [Nat.card_fun, Nat.card_fin, Nat.card_eq_fintype_card, goldilocks_card]
  have domainCard : Nat.card Position38 = 2^23 := by
    simp only [Position38, Nat.card_fin, V8Smz9DisjointCoset.domainSize]
  rw [lowCard, domainCard] at partition
  have lowSubtract : (58288 : Nat) - 1 = 58287 := by decide
  have highSubtract : (524288 : Nat) - 1 = 524287 := by decide
  rw [lowSubtract, highSubtract] at partition
  have lowWeighted :
      (badSupportLabels V8Smz9DisjointCoset.evaluationPoint 405 58288 prior direction).card *
          Nat.choose 524287 38 ≤
        19191588994328775603293919496651850544 * Nat.choose 524287 38 :=
    Nat.mul_le_mul_right (Nat.choose 524287 38) (bchksCount prior direction)
  have highWeighted :
      (badSupportLabels V8Smz9DisjointCoset.evaluationPoint 405 524288 prior direction).card *
          Nat.choose (2^23) 38 ≤ 42829439649 * Nat.choose (2^23) 38 :=
    Nat.mul_le_mul_right (Nat.choose (2^23) 38) (cubicCount prior direction)
  exact Nat.le_trans partition
    (Nat.add_le_add
      (Nat.add_le_add (Nat.le_refl (goldilocksModulus^5 * Nat.choose 58287 38))
        lowWeighted) highWeighted)

theorem unrestricted_mca38_of_geometric_counts
    (bchksCount : ∀ (prior : Fin 5 → Position38 → Goldilocks) (direction : Position38 → Goldilocks),
      (badSupportLabels V8Smz9DisjointCoset.evaluationPoint 405 58288 prior direction).card ≤
        19191588994328775603293919496651850544)
    (cubicCount : ∀ (prior : Fin 5 → Position38 → Goldilocks) (direction : Position38 → Goldilocks),
      (badSupportLabels V8Smz9DisjointCoset.evaluationPoint 405 524288 prior direction).card ≤
        42829439649) : UnrestrictedMca38 := by
  have naturalBound := universal_budget38_of_geometric_counts bchksCount cubicCount
  have rationalBound : (lineBudget38 : Rat) ≤
      (goldilocksModulus : Rat)^5*(Nat.choose 58287 38 : Rat) +
      19191588994328775603293919496651850544*(Nat.choose 524287 38 : Rat) +
      42829439649*(Nat.choose (2^23) 38 : Rat) := by exact_mod_cast naturalBound
  have denominatorPositive : (0 : Rat) < (Nat.choose (2^23) 38 : Rat) := by
    exact_mod_cast (Nat.choose_pos (by norm_num : 38 ≤ (2^23 : Nat)))
  have tailFloor : (42829439649 : Rat) ≤
      ((((2^23 : Nat)^2+3*2^23 : Nat) : Rat)/1643) := by norm_num
  unfold UnrestrictedMca38 publishedPartition38 w38 sampleDenominator38
  refine (div_le_div_of_nonneg_right rationalBound denominatorPositive.le).trans ?_
  calc
    _ = (goldilocksModulus : Rat)^5 *
          ((Nat.choose 58287 38 : Rat)/(Nat.choose (2^23) 38 : Rat)) +
        19191588994328775603293919496651850544 *
          ((Nat.choose 524287 38 : Rat)/(Nat.choose (2^23) 38 : Rat)) + 42829439649 := by
      field_simp [ne_of_gt denominatorPositive]
    _ ≤ _ := add_le_add (le_refl _) tailFloor

end
end HegemonCrypto.SmallWood.Mca38Closure



