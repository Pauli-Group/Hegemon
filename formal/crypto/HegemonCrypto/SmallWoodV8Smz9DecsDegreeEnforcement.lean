import HegemonCrypto.SmallWoodV8Smz9OracleExtraction
import HegemonCrypto.SmallWoodV8Smz9QromAccounting
import HegemonCrypto.SmallWoodDecsExtraction

/-!
# Exact SMZ9 committed-oracle degree enforcement

Split the actual `2^23 × 145` ideal committed oracle into its 140 data rows and five
masking rows. For any fixed such oracle with a data row outside the degree-387 code,
the fraction of full independent uniform 5-by-140 challenge matrices that make all
five masked combinations degree-387 codewords is at most `p^-5`.

This instantiates the proved residual/affine-fiber argument at the current coset and
oracle, not at the historical V4 dimensions. It does not assert that twenty accepted
openings establish full-domain codeword agreement. Nor does it identify the SHA-512
matrix derived after the Merkle commitment with an independent uniform matrix.
Those sampling, commitment, extraction and QROM transfers remain separate obligations.
-/

namespace HegemonCrypto.SmallWood.V8Smz9DecsDegreeEnforcement

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9OracleExtraction
open DecsExtraction

noncomputable section

abbrev CommittedOracle := V8Smz9LogicalOracle.CommittedOracle

/-- Data row projection is exactly the projection consumed by the existing inverse. -/
def committedDataRows (oracle : CommittedOracle) :
    Fin V8Smz9LogicalOracle.decsRowCount →
      Fin V8Smz9LogicalOracle.decsDomainSize → Goldilocks :=
  committedColumnValue oracle

/-- The five masks follow the 140 data words in every committed leaf. -/
def committedMaskRows (oracle : CommittedOracle) :
    Fin V8Smz9LogicalOracle.decsEta →
      Fin V8Smz9LogicalOracle.decsDomainSize → Goldilocks :=
  fun mask index => wordToGoldilocks
    (oracle index ⟨V8Smz9LogicalOracle.decsRowCount + mask.val,
      Nat.add_lt_add_left mask.isLt _⟩)

/-- A bad row is an actual non-codeword, not a supplied failure-probability bound. -/
def HasNonCodewordDataRow (oracle : CommittedOracle) : Prop :=
  ∃ row, ¬ IsDegreeBoundedWord Finset.univ smz9EvaluationPoint
    (committedDataRows oracle row) V8Smz9QromAccounting.decsPolynomialDegree

/-- Exact finite fraction over the independent uniform matrix space. -/
def smz9DegreeEnforcementFailureProbability (oracle : CommittedOracle) : Rat :=
  degreeEnforcementFailureProbability
    (degreeBound := V8Smz9QromAccounting.decsPolynomialDegree)
    smz9EvaluationPoint (committedDataRows oracle) (committedMaskRows oracle)

theorem smz9_noncodeword_degree_enforcement_failure_le
    (oracle : CommittedOracle)
    (badRow : HasNonCodewordDataRow oracle) :
    smz9DegreeEnforcementFailureProbability oracle ≤
      ((1 : Rat) / goldilocksModulus) ^ 5 := by
  have bound := uniform_matrix_degree_enforcement_failure_probability_le
    (degreeBound := V8Smz9QromAccounting.decsPolynomialDegree)
    (by decide) smz9EvaluationPoint smz9_evaluation_point_injective
    (committedDataRows oracle) (committedMaskRows oracle) badRow
  simpa only [smz9DegreeEnforcementFailureProbability,
    HegemonCrypto.FiniteFieldSampling.goldilocks_card,
    V8Smz9LogicalOracle.decsEta] using bound

/-- The current ledger's first term now bounds the exact current non-codeword event. -/
theorem smz9_noncodeword_degree_enforcement_failure_le_epsilon1
    (oracle : CommittedOracle)
    (badRow : HasNonCodewordDataRow oracle) :
    smz9DegreeEnforcementFailureProbability oracle ≤
      (V8Smz9QromAccounting.epsilon1Numerator : Rat) /
        V8Smz9QromAccounting.epsilon1Denominator := by
  calc
    smz9DegreeEnforcementFailureProbability oracle ≤
        ((1 : Rat) / goldilocksModulus) ^ 5 :=
      smz9_noncodeword_degree_enforcement_failure_le oracle badRow
    _ = (V8Smz9QromAccounting.epsilon1Numerator : Rat) /
        V8Smz9QromAccounting.epsilon1Denominator := by
      simp only [V8Smz9QromAccounting.epsilon1Numerator,
        V8Smz9QromAccounting.epsilon1Denominator,
        V8Smz9QromAccounting.goldilocksOrder,
        V8Smz9QromAccounting.decsEta, Nat.cast_pow, Nat.cast_one,
        div_pow, one_pow]
      rfl

end

end HegemonCrypto.SmallWood.V8Smz9DecsDegreeEnforcement
