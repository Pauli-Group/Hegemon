import Hegemon.Transaction.SmallWoodTranscriptBinding

set_option maxHeartbeats 0
set_option maxRecDepth 100000
set_option exponentiation.threshold 512

namespace Hegemon
namespace Transaction
namespace SmallWoodNoGrindingSoundness

open SmallWoodTranscriptBinding

def goldilocksOrder : Nat := 18446744069414584321
def activeRowCount : Nat := 699
def activePackingFactor : Nat := 64
def activePublicValueCount : Nat := 78
def activeConstraintDegree : Nat := 8

def ceilDiv (numerator denominator : Nat) : Nat :=
  (numerator + denominator - 1) / denominator

def activeWitnessPolynomialDegree : Nat :=
  activePackingFactor + activeProfile.nbOpenedEvals - 1

def activeBatchedConstraintPolynomialDegree : Nat :=
  activeConstraintDegree * activeWitnessPolynomialDegree

/--
Degree of the masked quotient committed through the PCS.  This is not the degree used by the
PIOP evaluation-soundness term: after cross multiplication, the verifier's consistency
discrepancy has the full batched-constraint degree.
-/
def activeConstraintPolynomialDegree : Nat :=
  activeBatchedConstraintPolynomialDegree - activePackingFactor

def activePiopConsistencyDiscrepancyDegree : Nat :=
  activeBatchedConstraintPolynomialDegree

def activePiopOpeningDomainSize : Nat :=
  goldilocksOrder - activePackingFactor

def activeLinearPolynomialDegree : Nat :=
  activePackingFactor + activeProfile.nbOpenedEvals - 1
    + activePackingFactor - 1

def polynomialWidth (degree : Nat) : Nat :=
  ceilDiv
    (degree + 1 - activeProfile.nbOpenedEvals)
    activePackingFactor

def activePolynomialCount : Nat :=
  activeRowCount + 2 * activeProfile.rho

def activeUnstackedColumnCount : Nat :=
  activeRowCount * polynomialWidth activeWitnessPolynomialDegree
    + activeProfile.rho * polynomialWidth activeConstraintPolynomialDegree
    + activeProfile.rho * polynomialWidth activeLinearPolynomialDegree

def activeLvcsRowCount : Nat :=
  (activePackingFactor + activeProfile.nbOpenedEvals) * activeProfile.beta

def activeLvcsColumnCount : Nat :=
  ceilDiv activeUnstackedColumnCount activeProfile.beta

def activeDecsPolynomialDegree : Nat :=
  activeLvcsColumnCount + activeProfile.decsNbOpenedEvals - 1

def fallingProduct (value count : Nat) : Nat :=
  (List.range count).foldl (fun product index => product * (value - index)) 1

def binomial (value count : Nat) : Nat :=
  (List.range count).foldl
    (fun result index => result * (value - index) / (index + 1))
    1

def supportsBitBound (bits numerator denominator : Nat) : Prop :=
  2 ^ bits * numerator ≤ denominator

def supports256BitBound (numerator denominator : Nat) : Prop :=
  supportsBitBound 256 numerator denominator

def supports260BitBound (numerator denominator : Nat) : Prop :=
  supportsBitBound 260 numerator denominator

def epsilon1Numerator : Nat :=
  binomial activeProfile.decsNbEvals (activeDecsPolynomialDegree + 2)

def epsilon1Denominator : Nat :=
  goldilocksOrder ^ activeProfile.decsEta

def epsilon2Numerator : Nat :=
  1

def epsilon2Denominator : Nat :=
  goldilocksOrder ^ activeProfile.rho

def epsilon3Numerator : Nat :=
  fallingProduct activePiopConsistencyDiscrepancyDegree activeProfile.nbOpenedEvals

def epsilon3Denominator : Nat :=
  fallingProduct activePiopOpeningDomainSize activeProfile.nbOpenedEvals

def epsilon4Numerator : Nat :=
  fallingProduct
    (activeLvcsColumnCount + activeProfile.decsNbOpenedEvals - 1)
    activeProfile.decsNbOpenedEvals

def epsilon4Denominator : Nat :=
  fallingProduct activeProfile.decsNbEvals activeProfile.decsNbOpenedEvals

def aggregateErrorNumerator : Nat :=
  epsilon1Numerator * epsilon2Denominator * epsilon3Denominator * epsilon4Denominator
    + epsilon2Numerator * epsilon1Denominator * epsilon3Denominator * epsilon4Denominator
    + epsilon3Numerator * epsilon1Denominator * epsilon2Denominator * epsilon4Denominator
    + epsilon4Numerator * epsilon1Denominator * epsilon2Denominator * epsilon3Denominator

def aggregateErrorDenominator : Nat :=
  epsilon1Denominator * epsilon2Denominator * epsilon3Denominator * epsilon4Denominator

def supports256BitBoundBool (numerator denominator : Nat) : Bool :=
  decide (2 ^ 256 * numerator ≤ denominator)

def supports260BitBoundBool (numerator denominator : Nat) : Bool :=
  decide (2 ^ 260 * numerator ≤ denominator)

def supportsBitsAtQueryBudget
    (bits queries numerator denominator : Nat) : Prop :=
  2 ^ bits * queries * numerator ≤ denominator

theorem active_profile_uses_rho_five :
    activeProfile.rho = 5 := by
  decide

theorem active_witness_polynomial_degree_is_68 :
    activeWitnessPolynomialDegree = 68 := by
  decide

theorem active_constraint_polynomial_degree_is_480 :
    activeConstraintPolynomialDegree = 480 := by
  decide

theorem active_batched_constraint_polynomial_degree_is_544 :
    activeBatchedConstraintPolynomialDegree = 544 := by
  decide

theorem active_piop_consistency_discrepancy_degree_is_544 :
    activePiopConsistencyDiscrepancyDegree = 544 := by
  decide

theorem active_piop_opening_domain_size_is_goldilocks_minus_64 :
    activePiopOpeningDomainSize = 18446744069414584257 := by
  decide

theorem active_linear_polynomial_degree_is_131 :
    activeLinearPolynomialDegree = 131 := by
  decide

theorem active_polynomial_count_is_709 :
    activePolynomialCount = 709 := by
  decide

theorem active_unstacked_column_count_is_749 :
    activeUnstackedColumnCount = 749 := by
  decide

theorem active_lvcs_row_count_is_483 :
    activeLvcsRowCount = 483 := by
  decide

theorem active_lvcs_column_count_is_107 :
    activeLvcsColumnCount = 107 := by
  decide

theorem active_decs_polynomial_degree_is_126 :
    activeDecsPolynomialDegree = 126 := by
  decide

theorem active_decs_binding_subset_size_is_128 :
    activeDecsPolynomialDegree + 2 = 128 := by
  decide

theorem active_epsilon1_supports_256_bits :
    supports256BitBound epsilon1Numerator epsilon1Denominator := by
  unfold supports256BitBound supportsBitBound
  decide

theorem active_epsilon2_supports_256_bits :
    supports256BitBound epsilon2Numerator epsilon2Denominator := by
  unfold supports256BitBound supportsBitBound
  decide

theorem active_epsilon3_supports_256_bits :
    supports256BitBound epsilon3Numerator epsilon3Denominator := by
  unfold supports256BitBound supportsBitBound
  decide

theorem active_epsilon4_supports_256_bits :
    supports256BitBound epsilon4Numerator epsilon4Denominator := by
  unfold supports256BitBound supportsBitBound
  decide

theorem active_single_query_aggregate_error_supports_256_bits :
    supports256BitBound aggregateErrorNumerator aggregateErrorDenominator := by
  unfold supports256BitBound supportsBitBound
  decide

theorem active_epsilon1_supports_260_bits :
    supports260BitBound epsilon1Numerator epsilon1Denominator := by
  unfold supports260BitBound supportsBitBound
  decide

theorem active_epsilon2_supports_260_bits :
    supports260BitBound epsilon2Numerator epsilon2Denominator := by
  unfold supports260BitBound supportsBitBound
  decide

theorem active_epsilon3_supports_260_bits :
    supports260BitBound epsilon3Numerator epsilon3Denominator := by
  unfold supports260BitBound supportsBitBound
  decide

theorem active_epsilon4_supports_260_bits :
    supports260BitBound epsilon4Numerator epsilon4Denominator := by
  unfold supports260BitBound supportsBitBound
  decide

theorem active_single_query_aggregate_error_supports_260_bits :
    supports260BitBound aggregateErrorNumerator aggregateErrorDenominator := by
  unfold supports260BitBound supportsBitBound
  decide

theorem active_aggregate_error_scales_with_query_budget
    {bits queries : Nat}
    (budget : 2 ^ bits * queries ≤ 2 ^ 256) :
    supportsBitsAtQueryBudget bits queries
      aggregateErrorNumerator aggregateErrorDenominator := by
  unfold supportsBitsAtQueryBudget
  calc
    2 ^ bits * queries * aggregateErrorNumerator ≤
        2 ^ 256 * aggregateErrorNumerator :=
      Nat.mul_le_mul_right aggregateErrorNumerator budget
    _ ≤ aggregateErrorDenominator :=
      active_single_query_aggregate_error_supports_256_bits

theorem active_no_grinding_profile_supports_256_bits :
    supports256BitBound epsilon1Numerator epsilon1Denominator
      ∧ supports256BitBound epsilon2Numerator epsilon2Denominator
      ∧ supports256BitBound epsilon3Numerator epsilon3Denominator
      ∧ supports256BitBound epsilon4Numerator epsilon4Denominator
      ∧ supports256BitBound aggregateErrorNumerator aggregateErrorDenominator := by
  exact ⟨active_epsilon1_supports_256_bits,
    active_epsilon2_supports_256_bits,
    active_epsilon3_supports_256_bits,
    active_epsilon4_supports_256_bits,
    active_single_query_aggregate_error_supports_256_bits⟩

theorem active_no_grinding_profile_supports_260_bits :
    supports260BitBound epsilon1Numerator epsilon1Denominator
      ∧ supports260BitBound epsilon2Numerator epsilon2Denominator
      ∧ supports260BitBound epsilon3Numerator epsilon3Denominator
      ∧ supports260BitBound epsilon4Numerator epsilon4Denominator
      ∧ supports260BitBound aggregateErrorNumerator aggregateErrorDenominator := by
  exact ⟨active_epsilon1_supports_260_bits,
    active_epsilon2_supports_260_bits,
    active_epsilon3_supports_260_bits,
    active_epsilon4_supports_260_bits,
    active_single_query_aggregate_error_supports_260_bits⟩

end SmallWoodNoGrindingSoundness
end Transaction
end Hegemon
