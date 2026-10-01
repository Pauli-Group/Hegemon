import Q38Rp05ActualPivot
import Q38Rp05ReachableBudget

/-! Rounding the actual two-witness endpoint loss. The request ledger is
explicit: a padded Schedule index does not establish this inequality. -/
namespace HegemonCrypto.SmallWood.Q38Rp05PrivacyNumerics

open HegemonCrypto.SmallWood.Q38Rp05ActualPivot

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 500000
-- The specified bound contains explicit powers through 2^512.
set_option exponentiation.threshold 1024

theorem loss_le_linear (total : Nat) (positive : 1 ≤ total) :
    loss total ≤ 8 * (total : ℝ) / (2 : ℝ)^256 := by
  have oneLe : (1 : ℝ) ≤ total := by exact_mod_cast positive
  have square : (total : ℝ) ≤ (total : ℝ)^2 := by nlinarith
  have squaredBound : 4 * (total : ℝ) * (2 ^ 512 : ℝ)⁻¹ ≤
      (2 * (total : ℝ) / (2 : ℝ)^256)^2 := by
    calc
      _ ≤ 4 * (total : ℝ)^2 * (2 ^ 512 : ℝ)⁻¹ :=
        mul_le_mul_of_nonneg_right
          (mul_le_mul_of_nonneg_left square (by norm_num)) (by positivity)
      _ = _ := by norm_num [div_pow, mul_pow]; ring
  have rootBound : Real.sqrt (4 * (total : ℝ) * (2 ^ 512 : ℝ)⁻¹) ≤
      2 * (total : ℝ) / (2 : ℝ)^256 :=
    Real.sqrt_le_iff.mpr ⟨by positivity, squaredBound⟩
  unfold loss
  calc
    _ ≤ 2 * (2 * (total : ℝ) / (2 : ℝ)^256) +
        4 * (total : ℝ) / (2 : ℝ)^256 :=
      add_le_add
        (mul_le_mul_of_nonneg_left rootBound (by norm_num : (0 : ℝ) ≤ 2)) le_rfl
    _ = _ := by ring

/-- The stronger ledger follows because the exact nonleaf P8 loss is zero. -/
theorem two_witness_strong_ledger (total requests : Nat)
    (positive : 1 ≤ total) (requestLedger : requests * 2^23 ≤ total) :
    2 * (requests : ℝ) * loss total ≤ 16 * (total : ℝ)^2 / (2 : ℝ)^279 := by
  have requestsBound : (requests : ℝ) ≤ (total : ℝ) / (2 : ℝ)^23 := by
    apply (le_div_iff₀ (by positivity)).2
    exact_mod_cast requestLedger
  calc
    _ ≤ 2 * (requests : ℝ) * (8 * (total : ℝ) / (2 : ℝ)^256) :=
      mul_le_mul_of_nonneg_left (loss_le_linear total positive) (by positivity)
    _ ≤ 2 * ((total : ℝ) / (2 : ℝ)^23) *
        (8 * (total : ℝ) / (2 : ℝ)^256) := by gcongr
    _ = _ := by norm_num; ring

theorem two_witness_spec_ledger (total requests : Nat)
    (positive : 1 ≤ total) (requestLedger : requests * 2^23 ≤ total) :
    2 * (requests : ℝ) * loss total ≤ 24 * (total : ℝ)^2 / (2 : ℝ)^279 := by
  apply (two_witness_strong_ledger total requests positive requestLedger).trans
  exact div_le_div_of_nonneg_right
    (mul_le_mul_of_nonneg_right (by norm_num : (16 : ℝ) ≤ 24) (sq_nonneg _))
    (by positivity)

theorem spec_ledger_at_lifetime_cap :
    24 * ((3 * 2^64 : Nat) : ℝ)^2 / (2 : ℝ)^279 =
      (27 / 32 : ℝ) * (2 : ℝ)^(-143 : ℤ) := by norm_num

/-- No externally supplied request ledger: even padded schedules satisfy
the rounded bound via the syntactically proved effective request count. -/
theorem effective_two_witness_spec_ledger (total requests : Nat) :
    2 * (Q38Rp05ReachableBudget.effectiveRequests requests total : ℝ) * loss total ≤
      24 * (total : ℝ)^2 / (2 : ℝ)^279 := by
  cases total with
  | zero => simp [Q38Rp05ReachableBudget.effectiveRequests, loss]
  | succ total =>
      exact two_witness_spec_ledger (total + 1) _ (by omega)
        (Q38Rp05ReachableBudget.effective_requests_ledger requests (total + 1))

end
end HegemonCrypto.SmallWood.Q38Rp05PrivacyNumerics
