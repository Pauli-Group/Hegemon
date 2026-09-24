import HegemonCrypto.SmallWoodV8Smz9SourceInactiveMerkleRightRoots

/-! All controls evaluate actual coefficient-DAG residuals at actual table
entries. The explicit all-one packed list is canonical as words, but none
of these controls claims typed witness validity or packed acceptance. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceInactiveMerkleRight

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

noncomputable section

theorem inactive_right_address_bound (input : Fin 2) (level : Fin 32) (limb : Fin 7) :
    inlineRightAddress input.val level.val limb.val < 17856 := by
  have indexBound : 224 * input.val + 7 * level.val + limb.val < 448 := by omega
  simp only [inlineRightAddress]
  omega

theorem inactive_right_flat_address (offset : Fin 448) :
    inlineRightAddress (inactiveRightInput offset).val (inactiveRightLevel offset).val
      (inactiveRightLimb offset).val = 16256 + 256 * (offset.val / 64) + offset.val % 64 := by
  simp only [inlineRightAddress, inactive_right_offset_decomposition]

theorem inactive_right_flat_actual_term (offset : Fin 448) :
    (inactiveRightAttempt offset).terms =
      [(16256 + 256 * (offset.val / 64) + offset.val % 64, 124 + offset.val / 224)] := by
  change [(inlineRightAddress (inactiveRightInput offset).val (inactiveRightLevel offset).val
    (inactiveRightLimb offset).val, 124 + (inactiveRightInput offset).val)] = _
  rw [inactive_right_flat_address]
  rfl

def nonzeroRightControlPacked : List Nat := List.replicate 43904 1

theorem nonzero_right_control_words_canonical : ExactWords 43904 nonzeroRightControlPacked := by
  constructor
  · exact List.length_replicate
  · intro value member
    have one : value = 1 := (List.mem_replicate.mp member).2
    rw [one]
    decide

theorem actual_inactive_right_all_448_one_control (offset : Fin 448) :
    actualCsrResidual (fun _ => 0) nonzeroRightControlPacked (inactiveRightAttempt offset) = 1 := by
  rw [inactiveRightAttempt, actual_inactive_right_residual]
  have bound := inactive_right_address_bound (inactiveRightInput offset)
    (inactiveRightLevel offset) (inactiveRightLimb offset)
  rw [show nonzeroRightControlPacked.getD
      (inlineRightAddress (inactiveRightInput offset).val (inactiveRightLevel offset).val
        (inactiveRightLimb offset).val) 0 = 1 by
    exact List.getD_replicate 1 (by omega)]
  simp only [sub_zero, Nat.cast_one, mul_one]

theorem actual_inactive_right_all_448_nonzero_control (offset : Fin 448) :
    actualCsrResidual (fun _ => 0) nonzeroRightControlPacked (inactiveRightAttempt offset) ≠ 0 := by
  rw [actual_inactive_right_all_448_one_control]
  decide

theorem actual_active_right_all_448_zero_control (offset : Fin 448) :
    actualCsrResidual (fun _ => 1) nonzeroRightControlPacked (inactiveRightAttempt offset) = 0 := by
  rw [inactiveRightAttempt, actual_inactive_right_residual]
  simp only [sub_self, zero_mul]

theorem actual_nonboolean_right_all_448_negative_one_control (offset : Fin 448) :
    actualCsrResidual (fun _ => 2) nonzeroRightControlPacked (inactiveRightAttempt offset) = -1 := by
  rw [inactiveRightAttempt, actual_inactive_right_residual]
  have bound := inactive_right_address_bound (inactiveRightInput offset)
    (inactiveRightLevel offset) (inactiveRightLimb offset)
  rw [show nonzeroRightControlPacked.getD
      (inlineRightAddress (inactiveRightInput offset).val (inactiveRightLevel offset).val
        (inactiveRightLimb offset).val) 0 = 1 by
    exact List.getD_replicate 1 (by omega)]
  norm_num

theorem actual_indexed_inactive_right_all_448_nonzero_control (offset : Fin 448) :
    ∃ entry, exactCsrAttempts[17838 + offset.val]? = some entry ∧
      actualCsrResidual (fun _ => 0) nonzeroRightControlPacked entry ≠ 0 :=
  ⟨inactiveRightAttempt offset, exact_inactive_right_all_448_lookup offset,
    actual_inactive_right_all_448_nonzero_control offset⟩

theorem inactive_right_endpoint_metadata :
    inactiveRightAttempt ⟨0,by decide⟩ = attempt 17838 17 0 1 [(16256,124)] 0 ∧
    inactiveRightAttempt ⟨223,by decide⟩ = attempt 18061 17 223 1 [(17055,124)] 0 ∧
    inactiveRightAttempt ⟨224,by decide⟩ = attempt 18062 17 224 1 [(17056,125)] 0 ∧
    inactiveRightAttempt ⟨447,by decide⟩ = attempt 18285 17 447 1 [(17855,125)] 0 := by decide


end
end HegemonCrypto.SmallWood.V8Smz9SourceInactiveMerkleRight

