import HegemonCrypto.NativePrivateSpendQ58CurrentMatrixRawOrder
import HegemonCrypto.NativePrivateSpendQ58CurrentDecsSampleDensity
import HegemonCrypto.NativePrivateSpendQ58CurrentTracePiopMass
import HegemonCrypto.UniformSubsetSampling
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentFinalCoefficientNumerics
namespace M
export NativePrivateSpendQ58CurrentMatrixRawOrder.M (matrixLoss)
end M
namespace D
export NativePrivateSpendQ58CurrentDecsSampleDensity (loss numerator)
end D
namespace P
export NativePrivateSpendQ58CurrentTracePiopMass (matrixLoss openingLoss)
end P
open HegemonCrypto.UniformSubsetSampling V8Smz9QromAccounting
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
noncomputable section

def sampleMajorant : Rat := (360447/8388551)^58+12*(13172/8388551)^58
def majorant : Rat := M.matrixLoss+sampleMajorant+P.matrixLoss+P.openingLoss
def polynomial (q d : Rat) := 12*q^2*d+150*q^3/2^512+20*q/2^512
def coefficient (q : Nat) : Rat :=
  polynomial q (M.matrixLoss+D.loss+P.matrixLoss+P.openingLoss)

private theorem current_choose_ratio_le_power (a b k : Nat) (fits : k ≤ b) :
    (Nat.choose a k : Rat) / (Nat.choose b k : Rat) ≤
      ((a : Rat) / ((b + 1 - k : Nat) : Rat))^k := by
  rw [←desc_factorial_ratio_eq_choose_ratio fits]
  have numeratorUpper : (a.descFactorial k : Rat) ≤ ((a^k : Nat) : Rat) := by
    exact_mod_cast Nat.descFactorial_le_pow a k
  have denominatorLower : (((b + 1 - k)^k : Nat) : Rat) ≤ (b.descFactorial k : Rat) := by
    exact_mod_cast Nat.pow_sub_le_descFactorial b k
  have positive : 0 < b + 1 - k :=
    Nat.sub_pos_of_lt (lt_of_le_of_lt fits (Nat.lt_succ_self b))
  have denominatorPositive : (0 : Rat) < (((b + 1 - k)^k : Nat) : Rat) := by
    exact_mod_cast pow_pos positive k
  calc
    _ ≤ ((a^k : Nat) : Rat) / (b.descFactorial k : Rat) :=
      div_le_div_of_nonneg_right numeratorUpper (Nat.cast_nonneg _)
    _ ≤ ((a^k : Nat) : Rat) / (((b + 1 - k)^k : Nat) : Rat) :=
      div_le_div_of_nonneg_left (Nat.cast_nonneg _) denominatorPositive denominatorLower
    _ = _ := by rw [Nat.cast_pow, Nat.cast_pow, div_pow]

private theorem current_union_ratio_le (a b denominator : Nat) (small root : Rat)
    (first : (a : Rat) / (denominator : Rat) ≤ small)
    (second : (b : Rat) / (denominator : Rat) ≤ root) :
    ((a + 12 * b : Nat) : Rat) / (denominator : Rat) ≤ small + 12 * root := by
  push_cast
  rw [add_div, mul_div_assoc]
  exact add_le_add first (mul_le_mul_of_nonneg_left second (by norm_num))

local macro "current_sample_union_eq%" : term => do
  let kernelName := Lean.Name.appendCore
    (Lean.Name.num `_private.HegemonCrypto.NativePrivateSpendQ58CurrentDecsSampleDensity 0)
    `HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentDecsSampleDensity.sample_union_bound_eq
  pure ⟨(Lean.mkCIdent kernelName).raw⟩

private theorem current_sample_numerator_eq :
    D.numerator = Nat.choose 360447 58 + 12 * Nat.choose 13172 58 := by
  delta D.numerator
  with_reducible
    exact no_implicit_lambda% (current_sample_union_eq%
      (Nat.choose 360447 58) (Nat.choose 13172 58))

theorem decs_loss_le : D.loss ≤ sampleMajorant := by
  have first : (Nat.choose 360447 58 : Rat)/(Nat.choose 8388608 58) ≤
      (360447/8388551 : Rat)^58 := by
    exact current_choose_ratio_le_power 360447 8388608 58 (by norm_num)
  have second : (Nat.choose 13172 58 : Rat)/(Nat.choose 8388608 58) ≤
      (13172/8388551 : Rat)^58 := by
    exact current_choose_ratio_le_power 13172 8388608 58 (by norm_num)
  have numeratorTransport := congrArg
    (fun value : Nat => (value : Rat) / (Nat.choose 8388608 58 : Rat))
    current_sample_numerator_eq
  change (D.numerator : Rat) / (Nat.choose 8388608 58 : Rat) ≤ _
  exact numeratorTransport.trans_le
    (current_union_ratio_le (Nat.choose 360447 58) (Nat.choose 13172 58)
      (Nat.choose 8388608 58) _ _ first second)

theorem coefficient_below_128 (q : Nat) (budget : q ≤ 3*2^64) :
    (coefficient q : ℝ) < (2 : ℝ)^(-128 : ℤ) := by
  have qb : (q : Rat) ≤ 3*2^64 := by exact_mod_cast budget
  have lb : M.matrixLoss+D.loss+P.matrixLoss+P.openingLoss ≤ majorant := by
    unfold majorant
    linarith [decs_loss_le]
  have positive : (0 : Rat) ≤ majorant := by
    have matrix : (0 : Rat) ≤ M.matrixLoss := by
      unfold M.matrixLoss
      exact div_nonneg (by norm_num) (Nat.cast_nonneg _)
    have sample : (0 : Rat) ≤ sampleMajorant := by
      unfold sampleMajorant
      positivity
    have piopMatrix : (0 : Rat) ≤ P.matrixLoss := by
      unfold P.matrixLoss
      exact pow_nonneg (div_nonneg zero_le_one (Nat.cast_nonneg _)) _
    have opening : (0 : Rat) ≤ P.openingLoss := by
      unfold P.openingLoss
      exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _)
    exact add_nonneg (add_nonneg (add_nonneg matrix sample) piopMatrix) opening
  have order : goldilocksOrder = 18446744069414584321 := by decide
  have numerator : fallingProduct 552 6 = 27529200278078400 := by decide
  have outsideCount : V8Smz9AdaptiveFiniteAccounting.distinctOutsideOpeningTupleCount =
      39402006141350511621114225210673602986862412529333074377438760896144125701637148142975581610924276996129155465239040 := by
    exact exact_distinct_outside_opening_tuple_count
  have power512 : (2 : Rat)^512 = (2 : Rat)^256 * (2 : Rat)^256 := by
    rw [show (512 : Nat) = 256 + 256 by rfl, pow_add]
  have bound : coefficient q < (1 : Rat)/2^128 := by
    calc
      coefficient q ≤ polynomial q majorant := by
        unfold coefficient polynomial
        gcongr
      _ ≤ polynomial (3*2^64) majorant := by
        unfold polynomial
        gcongr
      _ < _ := by
        norm_num [polynomial, majorant, sampleMajorant, M.matrixLoss, P.matrixLoss, P.openingLoss,
          Fintype.card_fun, Fintype.card_fin, goldilocks_card, goldilocksModulus,
          NativePrivateSpendQ58CurrentPiopEvents.conservativeCurrentDenominator,
          outsideCount, power512, order, numerator, piopOpenings]
  rw [show (2 : ℝ)^(-128 : ℤ) = (1 : ℝ)/2^128 by norm_num]
  have castBound := (Rat.cast_lt (K := ℝ)).mpr bound
  simpa only [Rat.cast_div, Rat.cast_one, Rat.cast_pow, Rat.cast_ofNat] using castBound
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentFinalCoefficientNumerics
