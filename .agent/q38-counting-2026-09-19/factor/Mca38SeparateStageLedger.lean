import Mathlib.Data.Nat.Choose.Bounds
import Mathlib.Tactic.NormNum
import Mathlib.Tactic.Ring

/-! Concrete q38 stage arithmetic without evaluating a choose recurrence at
8388608. The factorial bounds cancel; no sampling/protocol parameter changes.
The quantum expression is a ledger, not a substitute for its event reduction. -/
namespace HegemonCrypto.SmallWood.Mca38SeparateStageLedger

set_option autoImplicit false
set_option maxRecDepth 10000
set_option exponentiation.threshold 512

theorem q38_small_support_probability_le :
    (Nat.choose 65535 38 : Rat) / Nat.choose 8388608 38 ≤ (1 / 128 : Rat)^38 := by
  let a : Rat := Nat.choose 65535 38
  let b : Rat := Nat.choose 8388608 38
  let f : Rat := Nat.factorial 38
  have aNonnegative : 0 ≤ a := Nat.cast_nonneg _
  have bPositive : 0 < b := by
    dsimp [b]
    exact_mod_cast (Nat.choose_pos (by norm_num : 38 ≤ 8388608))
  have fPositive : 0 < f := by
    dsimp [f]
    positivity
  have upper : a ≤ (65535 : Rat)^38 / f := Nat.choose_le_pow_div 38 65535
  have lower : (8388571 : Rat)^38 / f ≤ b := by
    simpa only [Nat.reduceAdd, Nat.reduceSub, Nat.cast_pow, Nat.cast_ofNat] using
      (Nat.pow_le_choose (α := Rat) 38 8388608)
  have upperMul : a*f ≤ (65535 : Rat)^38 := (le_div_iff₀ fPositive).mp upper
  have lowerMul : (8388571 : Rat)^38 ≤ b*f := (div_le_iff₀ fPositive).mp lower
  have cross : a*(8388571 : Rat)^38 ≤ (65535 : Rat)^38*b := by
    calc
      _ ≤ a*(b*f) := mul_le_mul_of_nonneg_left lowerMul aNonnegative
      _ = (a*f)*b := by ring
      _ ≤ _ := mul_le_mul_of_nonneg_right upperMul bPositive.le
  have ratio : a/b ≤ (65535 : Rat)^38/(8388571 : Rat)^38 :=
    (div_le_div_iff₀ bPositive (by positivity)).mpr cross
  exact ratio.trans (by norm_num)

def matrixError : Rat :=
  (140 * 12310499043179 : Rat) / (18446744069414584321 : Rat)^5

theorem separate_decs_errors_below_265_bits :
    matrixError + (1 / 128 : Rat)^38 < (1 / 2 : Rat)^265 := by
  norm_num [matrixError]

/-- Conservative3R accounting, factor12 search loss, and factor2 for
event transport. Four coupling charges are recorded separately below. -/
theorem loose_transported_decs_main_below_129_bits :
    24 * (3 * (2 : Rat)^64)^2 *
      (matrixError + (1 / 128 : Rat)^38) < (1 / 2 : Rat)^129 := by
  norm_num [matrixError]

theorem four_coupling_charges_below_300_bits :
    8 * 576 * (3 * (2 : Rat)^64)^3 / (2 : Rat)^512 < (1 / 2 : Rat)^300 := by
  norm_num

end HegemonCrypto.SmallWood.Mca38SeparateStageLedger
