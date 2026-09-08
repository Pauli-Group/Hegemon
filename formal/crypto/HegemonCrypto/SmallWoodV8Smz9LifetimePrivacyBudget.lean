import HegemonCrypto.SmallWoodV8Smz9PostFinalPhysical

/-! Numerical composition of the three derived ideal-lifetime privacy
losses. These are explicit analysis resources, not a deployed lifetime
policy, concrete SHA-512 theorem, or production security authorization. -/

namespace HegemonCrypto.SmallWood.V8Smz9LifetimePrivacyBudget

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9PrivacyGameComposition V8Smz9CurrentPrivacyComposition V8Smz9CurrentPrivacyGame
open scoped Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

def selectedLoss (queries : Nat) (mass : ℝ) : ℝ :=
  Real.sqrt ((queries : ℝ) * mass) + (queries : ℝ) * mass / 2

def leafLoss (queries requests : Nat) : ℝ :=
  ((8388608 * requests : Nat) : ℝ) * selectedLoss queries (2 ^ 512 : ℝ)⁻¹

def finalLoss (queries requests : Nat) : ℝ :=
  (requests : ℝ) * selectedLoss queries ((goldilocksModulus : ℝ) ^ 3105)⁻¹

def hiddenLoss (queries requests : Nat) : ℝ :=
  (requests : ℝ) * hiddenPatchLoss queries

def privacyLoss (queries requests : Nat) : ℝ :=
  leafLoss queries requests + finalLoss queries requests + hiddenLoss queries requests

theorem selected_loss_nonnegative (queries : Nat) (mass : ℝ) (nonnegative : 0 ≤ mass) :
    0 ≤ selectedLoss queries mass := by
  unfold selectedLoss
  positivity

theorem selected_loss_mono_mass (queries : Nat) {left right : ℝ} (bounded : left ≤ right) :
    selectedLoss queries left ≤ selectedLoss queries right := by
  unfold selectedLoss
  gcongr

theorem large_coordinate_mass_bound (base : ℝ) (bounded : 2 ≤ base) :
    (base ^ 3105)⁻¹ ≤ (2 ^ 512 : ℝ)⁻¹ := by
  have positive : 0 < base := by linarith
  apply (inv_le_inv₀ (pow_pos positive _) (by positivity)).2
  calc
    (2 : ℝ) ^ 512 ≤ 2 ^ 3105 := pow_le_pow_right₀ (by norm_num) (by decide : 512 ≤ 3105)
    _ ≤ base ^ 3105 := by gcongr

theorem final_mass_le_tape_mass :
    ((goldilocksModulus : ℝ) ^ 3105)⁻¹ ≤ (2 ^ 512 : ℝ)⁻¹ :=
  large_coordinate_mass_bound _ (by norm_num [goldilocksModulus])

private theorem power512 : (2 : ℝ) ^ 512 = ((2 : ℝ) ^ 128) ^ 4 := by
  rw [← pow_mul]

theorem tape_selected_loss_at_analysis_queries (queries : Nat) (bounded : queries ≤ 2 ^ 65) :
    selectedLoss queries (2 ^ 512 : ℝ)⁻¹ ≤ (2 ^ 222 : ℝ)⁻¹ := by
  have queriesReal : (queries : ℝ) ≤ (2 : ℝ) ^ 65 := by exact_mod_cast bounded
  have exposure := mul_le_mul_of_nonneg_right queriesReal (by positivity : 0 ≤ (2 ^ 512 : ℝ)⁻¹)
  have squaredBound : (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ ≤ ((2 ^ 223 : ℝ)⁻¹) ^ 2 :=
    exposure.trans (by norm_num [power512])
  have rootBound : Real.sqrt ((queries : ℝ) * (2 ^ 512 : ℝ)⁻¹) ≤ (2 ^ 223 : ℝ)⁻¹ :=
    Real.sqrt_le_iff.mpr ⟨by positivity, squaredBound⟩
  have linearBound : (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2 ≤ (2 ^ 223 : ℝ)⁻¹ :=
    (div_le_div_of_nonneg_right exposure (by norm_num : (0 : ℝ) ≤ 2)).trans (by norm_num [power512])
  exact (add_le_add rootBound linearBound).trans (by norm_num [selectedLoss])

theorem privacy_loss_at_analysis_resources (queries requests : Nat)
    (queryBound : queries ≤ 2 ^ 65) (requestBound : requests ≤ 2 ^ 21) :
    privacyLoss queries requests ≤ (2 ^ 167 : ℝ)⁻¹ := by
  have requestsReal : (requests : ℝ) ≤ (2 : ℝ) ^ 21 := by exact_mod_cast requestBound
  have queriesReal : (queries : ℝ) ≤ (2 : ℝ) ^ 65 := by exact_mod_cast queryBound
  have selected := tape_selected_loss_at_analysis_queries queries queryBound
  have finalSelected := (selected_loss_mono_mass queries final_mass_le_tape_mass).trans selected
  have leaves : leafLoss queries requests ≤ (2 ^ 178 : ℝ)⁻¹ := by
    unfold leafLoss
    calc
      _ ≤ ((8388608 * requests : Nat) : ℝ) * (2 ^ 222 : ℝ)⁻¹ :=
        mul_le_mul_of_nonneg_left selected (Nat.cast_nonneg _)
      _ ≤ 8388608 * (2 : ℝ) ^ 21 * (2 ^ 222 : ℝ)⁻¹ := by
        push_cast
        gcongr
      _ = _ := by norm_num
  have final : finalLoss queries requests ≤ (2 ^ 201 : ℝ)⁻¹ := by
    unfold finalLoss
    calc
      _ ≤ (requests : ℝ) * (2 ^ 222 : ℝ)⁻¹ :=
        mul_le_mul_of_nonneg_left finalSelected (Nat.cast_nonneg _)
      _ ≤ (2 : ℝ) ^ 21 * (2 ^ 222 : ℝ)⁻¹ := by gcongr
      _ = _ := by norm_num
  have hidden : hiddenLoss queries requests ≤ (2 ^ 168 : ℝ)⁻¹ := by
    unfold hiddenLoss
    rw [current_hidden_patch_loss_closed_form]
    calc
      _ ≤ (2 : ℝ) ^ 21 * (4 * (2 : ℝ) ^ 65 / 2 ^ 256) := by gcongr
      _ = _ := by norm_num
  exact (add_le_add (add_le_add leaves final) hidden).trans (by norm_num [privacyLoss])

theorem two_witness_privacy_loss_below_target (queries requests : Nat)
    (queryBound : queries ≤ 2 ^ 65) (requestBound : requests ≤ 2 ^ 21) :
    2 * privacyLoss queries requests < (2 ^ 128 : ℝ)⁻¹ := by
  have budget := mul_le_mul_of_nonneg_left
    (privacy_loss_at_analysis_resources queries requests queryBound requestBound) (by norm_num : (0 : ℝ) ≤ 2)
  exact budget.trans_lt (by norm_num)

end
end HegemonCrypto.SmallWood.V8Smz9LifetimePrivacyBudget
