import HegemonCrypto.NativePrivateSpendQ58CurrentRoleEventPhysicalMass
import HegemonCrypto.NativePrivateSpendQ58CurrentFinalCoefficientNumerics
import SmzaRp05VectorRetention

namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedSourceArithmetic
open scoped BigOperators Classical
open SmzaChallengeStageTargets (Role)
open NativePrivateSpendQ58CurrentRoleEventPhysicalMass (localLoss)
open NativePrivateSpendQ58CurrentFinalCoefficientNumerics
open V8Smz9QromAccounting V8Smz9CoherentVectorMerkle
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
noncomputable section

def totalLoss : Rat := ∑ role : Role, localLoss role

private theorem current_total_loss_eq :
    totalLoss = M.matrixLoss+D.loss+P.matrixLoss+P.openingLoss := by
  have roles : (Finset.univ : Finset Role) =
      {.decsMatrix,.decsSample,.piopMatrix,.piopOpening} := by decide
  unfold totalLoss
  rw [roles]
  simp [localLoss, add_assoc]

private theorem current_total_loss_nonnegative : (0 : Rat) ≤ totalLoss := by
  rw [current_total_loss_eq]
  have matrix : (0 : Rat) ≤ M.matrixLoss := by
    unfold M.matrixLoss
    exact div_nonneg (by norm_num) (Nat.cast_nonneg _)
  have sample : (0 : Rat) ≤ D.loss := by
    unfold D.loss
    exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _)
  have piopMatrix : (0 : Rat) ≤ P.matrixLoss := by
    unfold P.matrixLoss
    exact pow_nonneg (div_nonneg zero_le_one (Nat.cast_nonneg _)) _
  have opening : (0 : Rat) ≤ P.openingLoss := by
    unfold P.openingLoss
    exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _)
  exact add_nonneg (add_nonneg (add_nonneg matrix sample) piopMatrix) opening

theorem total_loss_lt : totalLoss < (1 : Rat)/2^263 := by
  have upper : totalLoss ≤ majorant := by
    have roles : (Finset.univ : Finset Role) =
        {.decsMatrix,.decsSample,.piopMatrix,.piopOpening} := by decide
    unfold totalLoss
    rw [roles]
    simp [localLoss]
    unfold majorant
    linarith [decs_loss_le]
  have order : goldilocksOrder = 18446744069414584321 := by decide
  have numerator : fallingProduct 552 6 = 27529200278078400 := by decide
  have outsideCount : V8Smz9AdaptiveFiniteAccounting.distinctOutsideOpeningTupleCount =
      39402006141350511621114225210673602986862412529333074377438760896144125701637148142975581610924276996129155465239040 := by
    exact exact_distinct_outside_opening_tuple_count
  have power263 : (2 : Rat)^263 = (2 : Rat)^256 * (2 : Rat)^7 := by
    rw [show (263 : Nat) = 256 + 7 by rfl, pow_add]
  apply upper.trans_lt
  norm_num [majorant, sampleMajorant, M.matrixLoss, P.matrixLoss, P.openingLoss,
    Fintype.card_fun, Fintype.card_fin, goldilocks_card, goldilocksModulus,
    NativePrivateSpendQ58CurrentPiopEvents.conservativeCurrentDenominator,
    outsideCount, power263, order, numerator, piopOpenings]

variable {Counter : Type} [Fintype Counter] [DecidableEq Counter]

theorem vector_card_lower (counter : Counter) :
    2^512 ≤ Fintype.card (VectorOutput Counter) :=
  SmzaRp05VectorRetention.vector_output_cardinality_ge_digest counter

theorem accepted_arithmetic_below_128 (counter : Counter) (q : Nat)
    (budget : q ≤ 3*2^64) :
    6*(q:ℝ)^2*(totalLoss:ℝ)+72*(q:ℝ)^3/2^512+
      20*q/Fintype.card (VectorOutput Counter) < (2:ℝ)^(-128:ℤ) := by
  have lossNonnegative : (0 : ℝ) ≤ (totalLoss : ℝ) :=
    (Rat.cast_nonneg (K := ℝ)).mpr current_total_loss_nonnegative
  have denominator : (2 : ℝ)^512 ≤ Fintype.card (VectorOutput Counter) := by
    exact_mod_cast vector_card_lower counter
  have linear : 20*(q : ℝ)/Fintype.card (VectorOutput Counter) ≤
      20*(q : ℝ)/(2 : ℝ)^512 :=
    div_le_div_of_nonneg_left
      (mul_nonneg (by norm_num) (Nat.cast_nonneg q)) (by positivity) denominator
  have quadratic : (0 : ℝ) ≤ (q : ℝ)^2*(totalLoss : ℝ) :=
    mul_nonneg (sq_nonneg _) lossNonnegative
  have cubic : (0 : ℝ) ≤ (q : ℝ)^3/(2 : ℝ)^512 :=
    div_nonneg (pow_nonneg (Nat.cast_nonneg q) _) (pow_nonneg (by norm_num) _)
  have coefficientEq : (coefficient q : ℝ) =
      12*(q : ℝ)^2*(totalLoss : ℝ)+150*(q : ℝ)^3/2^512+20*q/2^512 := by
    rw [coefficient, polynomial, ←current_total_loss_eq]
    push_cast
    rfl
  have comparison :
      6*(q : ℝ)^2*(totalLoss : ℝ)+72*(q : ℝ)^3/2^512+
        20*q/Fintype.card (VectorOutput Counter) ≤ (coefficient q : ℝ) := by
    rw [coefficientEq]
    exact add_le_add (add_le_add
      (by simpa only [mul_assoc] using
        mul_le_mul_of_nonneg_right (show (6 : ℝ) ≤ 12 by norm_num) quadratic)
      (by simpa only [mul_div_assoc] using
        mul_le_mul_of_nonneg_right (show (72 : ℝ) ≤ 150 by norm_num) cubic)) linear
  exact comparison.trans_lt (coefficient_below_128 q budget)
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedSourceArithmetic
