import HegemonCrypto.SmallWoodV8Smz9SourceTailCsrTable
import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate

namespace HegemonCrypto.SmallWood.V8Smz9SourceTailCsrReadbacks

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceTailCsrTable
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField laneField_eq_packedWord)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem full_candidate_tail_flat_field_readback (statement : V8PublicStatement) (witness : V8Witness)
    (family : TailFamily) (offset : Nat) (bound : offset < family.width) (lane : Fin 64) :
    ((fullTypedSourceCandidate statement witness).getD
      ((647 + family.base + offset) * 64 + lane.val) 0 : F) =
      (tailFamilyWord statement witness (typedSourceFinals statement witness) family offset lane.val : F) := by
  have readback := congrArg (fun word : Nat => (word : F))
    (full_candidate_tail_family_readback statement witness family offset bound lane)
  change laneField _ _ _ = _ at readback
  have extent := tail_family_extent family
  rw [laneField_eq_packedWord _ _ _ (by omega)] at readback
  exact readback

theorem full_source_padding_field_zero (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 8) :
    ((fullTypedSourceCandidate statement witness).getD (41528 + index.val) 0 : F) = 0 := by
  have address : 41528 + index.val = 41408 + (120 + index.val) := by omega
  rw [address, full_candidate_source_word_readback statement witness ⟨120 + index.val,by omega⟩]
  simp only [stableSourceWord, if_neg (show ¬120 + index.val < 94 by omega),
    if_neg (show ¬120 + index.val < 112 by omega), if_neg (show ¬120 + index.val < 116 by omega),
    if_neg (show ¬120 + index.val < 120 by omega), Nat.cast_zero]

theorem source_boolean_config_copy (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) (index : Fin 4) :
    (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD (3 + index.val) 0 =
      stableSourceWord statement witness (booleanCopySource index.val) := by
  fin_cases index <;> rfl

theorem full_boolean_config_field_copy (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 4) :
    ((fullTypedSourceCandidate statement witness).getD (42115 + index.val) 0 : F) =
      ((fullTypedSourceCandidate statement witness).getD (41408 + booleanCopySource index.val) 0 : F) := by
  have rawBound : booleanCopySource index.val < 128 := by fin_cases index <;> decide
  rw [full_candidate_source_word_readback statement witness ⟨_,rawBound⟩]
  have address : 42115 + index.val = (647 + TailFamily.booleans.base + 0) * 64 + (3 + index.val) := by simp only [TailFamily.base]; omega
  rw [address, full_candidate_tail_flat_field_readback statement witness .booleans 0 (by decide)
    ⟨3 + index.val,by omega⟩]
  exact congrArg (fun word : Nat => (word : F)) (source_boolean_config_copy statement witness _ index)

theorem full_boolean_padding_field_zero (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 11) :
    ((fullTypedSourceCandidate statement witness).getD (42165 + index.val) 0 : F) = 0 := by
  have address : 42165 + index.val = (647 + TailFamily.booleans.base + 0) * 64 + (53 + index.val) := by simp only [TailFamily.base]; omega
  rw [address, full_candidate_tail_flat_field_readback statement witness .booleans 0 (by decide)
    ⟨53 + index.val,by omega⟩]
  change ((sourceBooleanValues statement.stablecoin witness.stablecoin
    (sourceAux statement.stablecoin witness.stablecoin)).getD (53 + index.val) 0 : F) = 0
  rw [List.getD_eq_default _ _ (by rw [source_boolean_shape]; omega), Nat.cast_zero]

theorem full_role_padding_unit_field (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 34) :
    ((fullTypedSourceCandidate statement witness).getD (41566 + index.val) 0 : F) = 1 := by
  have address : 41566 + index.val = (647 + TailFamily.roleDifference.base + 0) * 64 + (30 + index.val) := by simp only [TailFamily.base]; omega
  rw [address, full_candidate_tail_flat_field_readback statement witness .roleDifference 0 (by decide)
    ⟨30 + index.val,by omega⟩]
  change (sourceRoleWord statement witness _ (30 + index.val) 0 : F) = 1
  rw [source_unused_roles_unit statement witness _ _ _ (by omega)]
  exact Nat.cast_one

theorem full_role_padding_limbs_field (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 204) :
    ((fullTypedSourceCandidate statement witness).getD (41630 + index.val / 6 + 64 * (index.val % 6)) 0 : F) = 0 := by
  have address : 41630 + index.val / 6 + 64 * (index.val % 6) =
      (647 + TailFamily.roleDifference.base + (1 + index.val % 6)) * 64 + (30 + index.val / 6) := by
    simp only [TailFamily.base]
    omega
  rw [address, full_candidate_tail_flat_field_readback statement witness .roleDifference
    (1 + index.val % 6) (by change 1 + index.val % 6 < 7; omega) ⟨30 + index.val / 6,by omega⟩]
  change (sourceRoleWord statement witness _ (30 + index.val / 6) (1 + index.val % 6) : F) = 0
  rw [source_unused_roles_unit statement witness _ _ _ (by omega)]
  simp only [sourceUnitWord, if_neg (show 1 + index.val % 6 ≠ 0 by omega), Nat.cast_zero]

theorem full_role_padding_selector_field (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 34) :
    ((fullTypedSourceCandidate statement witness).getD (42014 + index.val) 0 : F) = 0 := by
  have address : 42014 + index.val = (647 + TailFamily.roleSelector.base + 0) * 64 + (30 + index.val) := by simp only [TailFamily.base]; omega
  rw [address, full_candidate_tail_flat_field_readback statement witness .roleSelector 0 (by decide)
    ⟨30 + index.val,by omega⟩]
  change (sourceRoleSelector statement witness _ (30 + index.val) : F) = 0
  rw [source_unused_selector_zero statement witness _ _ (by omega), Nat.cast_zero]

theorem full_role_padding_inverse_field (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 34) :
    ((fullTypedSourceCandidate statement witness).getD (42078 + index.val) 0 : F) = 1 := by
  have address : 42078 + index.val = (647 + TailFamily.roleInverse.base + 0) * 64 + (30 + index.val) := by simp only [TailFamily.base]; omega
  rw [address, full_candidate_tail_flat_field_readback statement witness .roleInverse 0 (by decide)
    ⟨30 + index.val,by omega⟩]
  change (sourceRoleInverse statement witness _ (30 + index.val) : F) = 1
  rw [source_unused_inverse_one statement witness _ _ (by omega), Nat.cast_one]

theorem full_range_padding_field_zero (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 38) :
    ((fullTypedSourceCandidate statement witness).getD (43866 + index.val) 0 : F) = 0 := by
  have readback := congrArg (fun word : Nat => (word : F))
    (full_candidate_last_padding_zero statement witness ⟨26 + index.val,by omega⟩
      (by change 26 ≤ 26 + index.val; omega))
  change laneField _ _ _ = _ at readback
  rw [laneField_eq_packedWord _ _ _ (by decide : 685 < 686)] at readback
  have address : 685 * 64 + (26 + index.val) = 43866 + index.val := by omega
  simpa only [V8Smz9SemanticDecoder.packedWord, address, Nat.cast_zero] using readback

theorem source_multiplication_padding_tuple (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) (lane : Nat) (padding : 33 ≤ lane) :
    sourceMultiplication statement witness aux lane = ({} : SourceMulTuple) := by
  simp only [sourceMultiplication, if_neg (show ¬lane < 18 by omega),
    if_neg (show ¬lane < 24 by omega), if_neg (show lane ≠ 24 by omega),
    if_neg (show ¬lane < 29 by omega), if_neg (show ¬lane < 33 by omega)]

theorem full_multiplication_padding_field_zero (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 93) :
    ((fullTypedSourceCandidate statement witness).getD (42273 + index.val / 3 + 64 * (index.val % 3)) 0 : F) = 0 := by
  have address : 42273 + index.val / 3 + 64 * (index.val % 3) =
      (647 + TailFamily.multiplication.base + index.val % 3) * 64 + (33 + index.val / 3) := by
    simp only [TailFamily.base]
    omega
  rw [address, full_candidate_tail_flat_field_readback statement witness .multiplication
    (index.val % 3) (by change index.val % 3 < 3; omega) ⟨33 + index.val / 3,by omega⟩]
  simp only [tailFamilyWord, source_multiplication_padding_tuple statement witness _
    (33 + index.val / 3) (by omega)]
  split_ifs <;> exact Nat.cast_zero

theorem full_numeric_padding_field_zero (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 18) :
    ((fullTypedSourceCandidate statement witness).getD (42222 + index.val) 0 : F) = 0 := by
  have address : 42222 + index.val = (647 + TailFamily.numeric.base + 0) * 64 + (46 + index.val) := by simp only [TailFamily.base]; omega
  rw [address, full_candidate_tail_flat_field_readback statement witness .numeric 0 (by decide)
    ⟨46 + index.val,by omega⟩]
  change ((sourceNumericValues (sourceAux statement.stablecoin witness.stablecoin)).getD (46 + index.val) 0 : F) = 0
  rw [List.getD_eq_default _ _ (by rw [source_numeric_shape]; omega), Nat.cast_zero]


end HegemonCrypto.SmallWood.V8Smz9SourceTailCsrReadbacks
