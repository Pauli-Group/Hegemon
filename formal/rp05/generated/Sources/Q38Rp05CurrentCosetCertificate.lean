import SmzaRp05DecsPointProjection
import HegemonCrypto.Goldilocks

/-!
# Kernel-checked current 406-point disjoint-coset certificate

This certificate verifies the literal finite Boolean predicate used by the
RP05 point projection, without importing the downstream current-coset module
and without trusting native evaluation.  `norm_num` reduces the finite
Goldilocks modular-power checks to proof-producing arithmetic certificates.
-/

namespace HegemonCrypto.SmallWood.Q38Rp05CurrentCosetCertificate

open HegemonCrypto.SmallWood
open SmzaRp05DecsPointProjection

set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 1000000
set_option exponentiation.threshold 1024

private theorem point_power_ne_shift_power :
    ∀ point : Fin 406,
      (point.val : Goldilocks) ^ (2 ^ 23) ≠ (406 : Goldilocks) ^ (2 ^ 23) := by
  have concrete : ∀ point : Fin 406,
      (point.val : ZMod 18446744069414584321) ^ (2 ^ 23) ≠
        ((406 : Nat) : ZMod 18446744069414584321) ^ (2 ^ 23) := by
    intro point
    fin_cases point <;> reduce_mod_char <;> decide
  intro point
  change
    (point.val : ZMod 18446744069414584321) ^ (2 ^ 23) ≠
      ((406 : Nat) : ZMod 18446744069414584321) ^ (2 ^ 23)
  exact concrete point

private theorem every_interpolation_point_avoids_shift_power :
    ∀ point : Fin 406,
      point.val = 0 ∨
        (((point.val : Goldilocks) * (406 : Goldilocks)⁻¹) ^ (2 ^ 23) ≠ 1) := by
  intro point
  by_cases pointZero : point.val = 0
  · exact Or.inl pointZero
  · right
    have shiftNe : (406 : Goldilocks) ≠ 0 := by decide
    have inversePower :
        (406 : Goldilocks)⁻¹ ^ (2 ^ 23) * (406 : Goldilocks) ^ (2 ^ 23) = 1 := by
      rw [← mul_pow, inv_mul_cancel₀ shiftNe, one_pow]
    intro ratioPower
    have multiplied := congrArg
      (fun value : Goldilocks => value * (406 : Goldilocks) ^ (2 ^ 23))
      ratioPower
    rw [mul_pow, one_mul] at multiplied
    have powerEquality :
        (point.val : Goldilocks) ^ (2 ^ 23) = (406 : Goldilocks) ^ (2 ^ 23) := by
      calc
        (point.val : Goldilocks) ^ (2 ^ 23) =
            (point.val : Goldilocks) ^ (2 ^ 23) * 1 := by rw [mul_one]
        _ = (point.val : Goldilocks) ^ (2 ^ 23) *
            ((406 : Goldilocks)⁻¹ ^ (2 ^ 23) * (406 : Goldilocks) ^ (2 ^ 23)) := by
              rw [inversePower]
        _ = ((point.val : Goldilocks) ^ (2 ^ 23) * (406 : Goldilocks)⁻¹ ^ (2 ^ 23)) *
            (406 : Goldilocks) ^ (2 ^ 23) := by rw [mul_assoc]
        _ = (406 : Goldilocks) ^ (2 ^ 23) := multiplied
    exact (point_power_ne_shift_power point) powerEquality

private theorem all_candidate_coordinates_checked :
    (List.range 406).all (fun point => decide
      (point = 0 ∨ (((point : Goldilocks) * (406 : Goldilocks)⁻¹) ^ (2 ^ 23) ≠ 1))) = true := by
  apply List.all_eq_true.mpr
  intro point member
  have pointLt : point < 406 := List.mem_range.mp member
  rcases every_interpolation_point_avoids_shift_power ⟨point, pointLt⟩ with zero | avoids
  · rw [decide_eq_true_eq]
    exact Or.inl zero
  · rw [decide_eq_true_eq]
    exact Or.inr avoids

theorem current_candidate_406_valid :
    SmzaRp05DecsPointProjection.disjointCandidate 406 406 = true := by
  unfold SmzaRp05DecsPointProjection.disjointCandidate
  simp only [SmzaRp05DecsPointProjection.domainSize, Bool.and_eq_true,
    decide_eq_true_eq]
  exact ⟨⟨by decide, by decide⟩, all_candidate_coordinates_checked⟩

end HegemonCrypto.SmallWood.Q38Rp05CurrentCosetCertificate
