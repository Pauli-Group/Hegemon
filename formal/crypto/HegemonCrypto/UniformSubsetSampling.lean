import HegemonCrypto.FiniteFieldSampling
import HegemonCrypto.SmallWoodFixedSampling
import Hegemon.Transaction.SmallWoodNoGrindingSoundness
import Mathlib.Data.Finset.Powerset
import Mathlib.Data.Nat.Factorial.BigOperators
import Mathlib.Tactic.FieldSimp

/-!
# Exact uniform subset sampling

SmallWood's third and fourth algebraic failure terms are hypergeometric probabilities:
the verifier samples distinct positions without replacement and loses only when every sampled
position belongs to a bounded bad set.  This module derives that probability from finite-set
cardinalities and connects it to the descending-product arithmetic used by the production
security ledger.
-/

namespace HegemonCrypto.UniformSubsetSampling

open Hegemon.Transaction.SmallWoodNoGrindingSoundness
open Hegemon.Transaction.SmallWoodTranscriptBinding
open HegemonCrypto.SmallWood.FixedSampling

variable {Element : Type*} [DecidableEq Element]

/-- All `sampleSize`-element subsets of one finite ambient set. -/
def sampleSpace (ambient : Finset Element) (sampleSize : Nat) :
    Finset (Finset Element) :=
  ambient.powersetCard sampleSize

/-- Fixed-size samples entirely contained in a designated bad set. -/
def badSamples
    (ambient bad : Finset Element)
    (sampleSize : Nat) : Finset (Finset Element) :=
  (sampleSpace ambient sampleSize).filter fun sample => sample ⊆ bad

theorem bad_samples_eq_bad_powerset
    {ambient bad : Finset Element}
    {sampleSize : Nat}
    (badSubset : bad ⊆ ambient) :
    badSamples ambient bad sampleSize = bad.powersetCard sampleSize := by
  ext sample
  constructor
  · intro membership
    have filtered := Finset.mem_filter.mp membership
    exact Finset.mem_powersetCard.mpr
      ⟨filtered.2, (Finset.mem_powersetCard.mp filtered.1).2⟩
  · intro membership
    have badMembership := Finset.mem_powersetCard.mp membership
    apply Finset.mem_filter.mpr
    constructor
    · exact Finset.mem_powersetCard.mpr
        ⟨badMembership.1.trans badSubset, badMembership.2⟩
    · exact badMembership.1

/-- Exact number of fixed-size samples contained in a fixed bad set. -/
theorem bad_samples_card
    {ambient bad : Finset Element}
    {sampleSize : Nat}
    (badSubset : bad ⊆ ambient) :
    (badSamples ambient bad sampleSize).card =
      Nat.choose bad.card sampleSize := by
  rw [bad_samples_eq_bad_powerset badSubset, Finset.card_powersetCard]

omit [DecidableEq Element] in
/-- Exact number of fixed-size samples in the ambient set. -/
theorem sample_space_card
    (ambient : Finset Element)
    (sampleSize : Nat) :
    (sampleSpace ambient sampleSize).card =
      Nat.choose ambient.card sampleSize := by
  exact Finset.card_powersetCard sampleSize ambient

/-- Uniform failure probability for choosing a fixed-size subset of a bad set. -/
def uniformBadSubsetProbability
    (ambient bad : Finset Element)
    (sampleSize : Nat) : Rat :=
  (badSamples ambient bad sampleSize).card /
    (sampleSpace ambient sampleSize).card

/-- The uniform bad-subset probability is exactly the hypergeometric ratio. -/
theorem uniform_bad_subset_probability_exact
    {ambient bad : Finset Element}
    {sampleSize : Nat}
    (badSubset : bad ⊆ ambient) :
    uniformBadSubsetProbability ambient bad sampleSize =
      (Nat.choose bad.card sampleSize : Rat) /
        Nat.choose ambient.card sampleSize := by
  simp only [uniformBadSubsetProbability, bad_samples_card badSubset,
    sample_space_card]

/--
If the bad set has at most `badBound` elements, the hypergeometric failure probability is bounded
by the same ratio with `badBound` in the numerator.
-/
theorem uniform_bad_subset_probability_le
    {ambient bad : Finset Element}
    {sampleSize badBound : Nat}
    (badSubset : bad ⊆ ambient)
    (badCardBound : bad.card ≤ badBound)
    (sampleFits : sampleSize ≤ ambient.card) :
    uniformBadSubsetProbability ambient bad sampleSize ≤
      (Nat.choose badBound sampleSize : Rat) /
        Nat.choose ambient.card sampleSize := by
  rw [uniform_bad_subset_probability_exact badSubset]
  have denominatorPositive :
      (0 : Rat) < Nat.choose ambient.card sampleSize := by
    exact_mod_cast Nat.choose_pos sampleFits
  apply (div_le_div_iff_of_pos_right denominatorPositive).2
  exact_mod_cast Nat.choose_le_choose sampleSize badCardBound

/-- The ledger's explicit fold is the standard descending factorial. -/
theorem falling_product_eq_desc_factorial
    (value count : Nat) :
    fallingProduct value count = value.descFactorial count := by
  induction count with
  | zero =>
      simp [fallingProduct]
  | succ count inductionHypothesis =>
      simp only [fallingProduct, List.range_succ, List.foldl_append,
        List.foldl_cons, List.foldl_nil]
      change
        fallingProduct value count * (value - count) =
          value.descFactorial (count + 1)
      rw [inductionHypothesis, Nat.descFactorial_succ]
      exact Nat.mul_comm _ _

/-- Descending-factorial ratios and subset-cardinality ratios are exactly equal. -/
theorem desc_factorial_ratio_eq_choose_ratio
    {bad ambient sampleSize : Nat}
    (sampleFitsAmbient : sampleSize ≤ ambient) :
    (bad.descFactorial sampleSize : Rat) /
        ambient.descFactorial sampleSize =
      (Nat.choose bad sampleSize : Rat) /
        Nat.choose ambient sampleSize := by
  rw [Nat.descFactorial_eq_factorial_mul_choose,
    Nat.descFactorial_eq_factorial_mul_choose]
  have factorialNonzero : (sampleSize.factorial : Rat) ≠ 0 := by
    exact_mod_cast Nat.factorial_ne_zero sampleSize
  have ambientChooseNonzero :
      (Nat.choose ambient sampleSize : Rat) ≠ 0 := by
    exact_mod_cast Nat.choose_ne_zero sampleFitsAmbient
  push_cast
  field_simp

/--
The active PIOP evaluation term is exactly the upper bound for drawing five distinct roots from
a nonzero verifier-consistency discrepancy with at most 544 roots.  The ambient set excludes the
64 packing points because the production verifier rejects those points before evaluating a quotient.
-/
theorem active_epsilon3_is_uniform_root_subset_bound :
    (epsilon3Numerator : Rat) / epsilon3Denominator =
      (Nat.choose activePiopConsistencyDiscrepancyDegree
          activeProfile.nbOpenedEvals : Rat) /
        Nat.choose activePiopOpeningDomainSize activeProfile.nbOpenedEvals := by
  rw [epsilon3Numerator, epsilon3Denominator,
    falling_product_eq_desc_factorial, falling_product_eq_desc_factorial]
  exact desc_factorial_ratio_eq_choose_ratio (by decide)

/--
The active DECS opening term is exactly the probability bound for drawing all 20 leaves from a
bad set of size `activeLvcsColumnCount + 19` inside the `2^20`-leaf commitment.
-/
theorem active_epsilon4_is_uniform_bad_leaf_subset_bound :
    (epsilon4Numerator : Rat) / epsilon4Denominator =
      (Nat.choose
          (activeLvcsColumnCount + activeProfile.decsNbOpenedEvals - 1)
          activeProfile.decsNbOpenedEvals : Rat) /
        Nat.choose activeProfile.decsNbEvals
          activeProfile.decsNbOpenedEvals := by
  rw [epsilon4Numerator, epsilon4Denominator,
    falling_product_eq_desc_factorial, falling_product_eq_desc_factorial]
  exact desc_factorial_ratio_eq_choose_ratio (by decide)

/--
The exact executable fixed-work sampler, conditioned on not rejecting for exhaustion, has the same
bad-subset probability as ideal uniform sampling without replacement.  This is derived from equal
finite preimage counts, not assumed from an informal rejection-sampling argument.
-/
theorem fixed_sampler_conditional_bad_probability_eq_uniform
    (bad : Finset DomainIndex) :
    conditionalBadSubsetProbability bad =
      uniformBadSubsetProbability
        (Finset.univ : Finset DomainIndex) bad openingCount := by
  rw [conditional_bad_subset_probability_exact,
    uniform_bad_subset_probability_exact (Finset.subset_univ bad)]
  have domainCard :
      Fintype.card DomainIndex = domainSize :=
    Fintype.card_fin domainSize
  rw [Finset.card_univ, domainCard]

/--
For the active LVCS bad-set cardinality, the executable fixed sampler realizes exactly the fourth
SmallWood soundness term.
-/
theorem active_epsilon4_is_fixed_sampler_conditional_bad_bound
    (bad : Finset DomainIndex)
    (badCard :
      bad.card =
        activeLvcsColumnCount + activeProfile.decsNbOpenedEvals - 1) :
    conditionalBadSubsetProbability bad =
      (epsilon4Numerator : Rat) / epsilon4Denominator := by
  rw [conditional_bad_subset_probability_exact, badCard]
  have openingCountEquation :
      openingCount = activeProfile.decsNbOpenedEvals := by
    decide
  rw [openingCountEquation]
  exact active_epsilon4_is_uniform_bad_leaf_subset_bound.symm

section PolynomialRoots

variable {F : Type*} [Field F] [Fintype F] [DecidableEq F]

/--
Sampling distinct field points without replacement hits only roots of a nonzero polynomial with
probability bounded by the exact descending-factorial expression.
-/
theorem uniform_root_subset_probability_le
    (polynomial : Polynomial F)
    (nonzero : polynomial ≠ 0)
    (sampleSize degreeBound : Nat)
    (degreeBounded : polynomial.natDegree ≤ degreeBound)
    (sampleFits : sampleSize ≤ Fintype.card F) :
    uniformBadSubsetProbability
        (Finset.univ : Finset F)
        (FiniteFieldSampling.rootSet polynomial)
        sampleSize ≤
      (Nat.choose degreeBound sampleSize : Rat) /
        Nat.choose (Fintype.card F) sampleSize := by
  apply uniform_bad_subset_probability_le
  · exact Finset.subset_univ _
  · exact (FiniteFieldSampling.root_set_card_le_nat_degree nonzero).trans degreeBounded
  · simpa using sampleFits

end PolynomialRoots

end HegemonCrypto.UniformSubsetSampling
