import HegemonCrypto.NativePrivateSpendQ58CurrentFreshAccounting

namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentFreshNumerics
open NativePrivateSpendQ58CurrentFreshAccounting

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option exponentiation.threshold 1024

/-- A deliberately rounded bound; it is not a measured implementation cost.
Q includes all oracle consumers and requests in the one execution. -/
theorem fresh_loss_below_128 (queries : Nat) (budget : queries ≤ 3 * 2^64) :
    freshLifetimeLoss queries < (2 : ℝ)^(-128 : ℤ) := by
  have qNonnegative : (0 : ℝ) ≤ queries := Nat.cast_nonneg _
  have qBound : (queries : ℝ) ≤ ((3 * 2^64 : Nat) : ℝ) := by exact_mod_cast budget
  have squareBound : (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ ≤
      ((2 : ℝ)^(-223 : ℤ))^2 := by
    calc
      _ ≤ ((3 * 2^64 : Nat) : ℝ) * (2 ^ 512 : ℝ)⁻¹ :=
        mul_le_mul_of_nonneg_right qBound (by positivity)
      _ ≤ _ := by norm_num
  have rootBound : Real.sqrt ((queries : ℝ) * (2 ^ 512 : ℝ)⁻¹) ≤
      (2 : ℝ)^(-223 : ℤ) :=
    Real.sqrt_le_iff.mpr ⟨by positivity, squareBound⟩
  have linearBound : (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2 ≤
      ((3 * 2^64 : Nat) : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2 := by
    exact div_le_div_of_nonneg_right
      (mul_le_mul_of_nonneg_right qBound (by positivity)) (by norm_num)
  calc
    freshLifetimeLoss queries ≤
        (queries : ℝ) * ((2 : ℝ)^(-223 : ℤ) +
          ((3 * 2^64 : Nat) : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2) :=
      mul_le_mul_of_nonneg_left (add_le_add rootBound linearBound) qNonnegative
    _ ≤ ((3 * 2^64 : Nat) : ℝ) * ((2 : ℝ)^(-223 : ℤ) +
          ((3 * 2^64 : Nat) : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2) :=
      mul_le_mul_of_nonneg_right qBound (by positivity)
    _ < (2 : ℝ)^(-157 : ℤ) := by norm_num
    _ < _ := by norm_num

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentFreshNumerics
