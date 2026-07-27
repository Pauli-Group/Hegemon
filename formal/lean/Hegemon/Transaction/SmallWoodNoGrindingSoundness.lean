import Hegemon.Transaction.SmallWoodTranscriptBinding

set_option maxHeartbeats 0
set_option maxRecDepth 100000

namespace Hegemon
namespace Transaction
namespace SmallWoodNoGrindingSoundness

open SmallWoodTranscriptBinding

def goldilocksOrder : Nat := 18446744069414584321
def activeRowCount : Nat := 1531
def activePackingFactor : Nat := 64
def activePublicValueCount : Nat := 78
def activeConstraintDegree : Nat := 8

def ceilDiv (numerator denominator : Nat) : Nat :=
  (numerator + denominator - 1) / denominator

def activeWitnessPolynomialDegree : Nat :=
  activePackingFactor + activeProfile.nbOpenedEvals - 1

def activeConstraintPolynomialDegree : Nat :=
  activeConstraintDegree
      * (activePackingFactor + activeProfile.nbOpenedEvals - 1)
    - activePackingFactor

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

def fallingProduct (value count : Nat) : Nat :=
  (List.range count).foldl (fun product index => product * (value - index)) 1

def supports128BitBound (numerator denominator : Nat) : Prop :=
  2 ^ 128 * numerator ≤ denominator

def epsilon1Numerator : Nat :=
  (activeProfile.decsNbEvals + 2 * activeConstraintDegree ^ activeProfile.beta)
    * (goldilocksOrder + activeLvcsRowCount ^ (activeProfile.decsEta + 1))

def epsilon1Denominator : Nat :=
  activeConstraintDegree ^ activeProfile.beta
    * goldilocksOrder ^ (activeProfile.decsEta + 1)

def epsilon2Numerator : Nat :=
  goldilocksOrder
    + (activePackingFactor + activePublicValueCount) ^ (activeProfile.rho + 1)

def epsilon2Denominator : Nat :=
  goldilocksOrder ^ (activeProfile.rho + 1)

def epsilon3Numerator : Nat :=
  fallingProduct activeConstraintPolynomialDegree activeProfile.nbOpenedEvals

def epsilon3Denominator : Nat :=
  fallingProduct goldilocksOrder activeProfile.nbOpenedEvals

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

def supports128BitBoundBool (numerator denominator : Nat) : Bool :=
  decide (2 ^ 128 * numerator ≤ denominator)

def supportsBitsAtQueryBudget
    (bits queries numerator denominator : Nat) : Prop :=
  2 ^ bits * queries * numerator ≤ denominator

theorem active_profile_uses_rho_three :
    activeProfile.rho = 3 := by
  decide

theorem active_witness_polynomial_degree_is_66 :
    activeWitnessPolynomialDegree = 66 := by
  decide

theorem active_constraint_polynomial_degree_is_464 :
    activeConstraintPolynomialDegree = 464 := by
  decide

theorem active_linear_polynomial_degree_is_129 :
    activeLinearPolynomialDegree = 129 := by
  decide

theorem active_polynomial_count_is_1537 :
    activePolynomialCount = 1537 := by
  decide

theorem active_unstacked_column_count_is_1561 :
    activeUnstackedColumnCount = 1561 := by
  decide

theorem active_lvcs_row_count_is_134 :
    activeLvcsRowCount = 134 := by
  decide

theorem active_lvcs_column_count_is_781 :
    activeLvcsColumnCount = 781 := by
  decide

theorem active_epsilon1_supports_128_bits :
    supports128BitBound epsilon1Numerator epsilon1Denominator := by
  simp only [supports128BitBound]
  decide

theorem active_epsilon2_supports_128_bits :
    supports128BitBound epsilon2Numerator epsilon2Denominator := by
  simp only [supports128BitBound]
  decide

theorem active_epsilon3_supports_128_bits :
    supports128BitBound epsilon3Numerator epsilon3Denominator := by
  simp only [supports128BitBound]
  decide

theorem active_epsilon4_supports_128_bits :
    supports128BitBound epsilon4Numerator epsilon4Denominator := by
  simp only [supports128BitBound]
  decide

theorem active_single_query_aggregate_error_supports_128_bits :
    supports128BitBound aggregateErrorNumerator aggregateErrorDenominator := by
  simp only [supports128BitBound]
  decide

theorem active_aggregate_error_scales_with_query_budget
    {bits queries : Nat}
    (budget : 2 ^ bits * queries ≤ 2 ^ 128) :
    supportsBitsAtQueryBudget bits queries
      aggregateErrorNumerator aggregateErrorDenominator := by
  unfold supportsBitsAtQueryBudget
  calc
    2 ^ bits * queries * aggregateErrorNumerator ≤
        2 ^ 128 * aggregateErrorNumerator :=
      Nat.mul_le_mul_right aggregateErrorNumerator budget
    _ ≤ aggregateErrorDenominator :=
      active_single_query_aggregate_error_supports_128_bits

theorem active_no_grinding_profile_supports_128_bits :
    supports128BitBound epsilon1Numerator epsilon1Denominator
      ∧ supports128BitBound epsilon2Numerator epsilon2Denominator
      ∧ supports128BitBound epsilon3Numerator epsilon3Denominator
      ∧ supports128BitBound epsilon4Numerator epsilon4Denominator
      ∧ supports128BitBound aggregateErrorNumerator aggregateErrorDenominator := by
  exact ⟨active_epsilon1_supports_128_bits,
    active_epsilon2_supports_128_bits,
    active_epsilon3_supports_128_bits,
    active_epsilon4_supports_128_bits,
    active_single_query_aggregate_error_supports_128_bits⟩

end SmallWoodNoGrindingSoundness
end Transaction
end Hegemon
