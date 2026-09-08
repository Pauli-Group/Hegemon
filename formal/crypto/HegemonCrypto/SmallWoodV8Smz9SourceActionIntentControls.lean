import HegemonCrypto.SmallWoodV8Smz9SourceActionIntentResiduals

/-! These controls use actual table entries and the actual coefficient DAG.
Their explicitly constructed packed words are canonical, but they are not
asserted to be typed-valid witnesses or fully accepted relation assignments. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceActionIntentInitial
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
open HegemonCrypto.SmallWood.V8Smz9ActionIntentSourceWords
open HegemonCrypto.SmallWood.V8Smz9FullRateSourceFrames
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000

def actionZeroTarget (block lane : Nat) : Nat :=
  if lane < 8 then 0 else fullRateFrameConstant 0 block lane

def actionControlPacked (block lane delta : Nat) : List Nat :=
  (List.range 43904).map fun address =>
    if address = hashInitialIndex (79 + block) lane then actionZeroTarget block lane + delta else 0

theorem action_control_addresses (block : Fin 15) (lane : Fin 16) :
    hashInitialIndex (79 + block.val) lane.val < 43904 ∧
    hashFinalIndex (79 + block.val - 1) lane.val < 43904 ∧
    hashFinalIndex (79 + block.val - 1) lane.val ≠ hashInitialIndex (79 + block.val) lane.val := by
  simp only [hashInitialIndex, hashFinalIndex, hashRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
    hashRowsPerGroup, hashFinalRowOffset]
  omega

theorem action_control_readback (block lane delta : Nat) (address : Fin 43904) :
    (actionControlPacked block lane delta).getD address.val 0 =
      if address.val = hashInitialIndex (79 + block) lane then actionZeroTarget block lane + delta else 0 := by
  simp [actionControlPacked, List.getD_eq_getElem?_getD, address.isLt]

theorem action_zero_target_plus_one_canonical (block lane : Nat) :
    actionZeroTarget block lane + 1 < Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus := by
  unfold actionZeroTarget fullRateFrameConstant fullRateSourceDomain fullRateSourceBlocks
  split_ifs <;> decide

theorem action_control_canonical (block : Fin 15) (lane : Fin 16) (delta : Fin 2) :
    ExactWords 43904 (actionControlPacked block.val lane.val delta.val) := by
  constructor
  · simp only [actionControlPacked, List.length_map, List.length_range]
  · intro value member
    obtain ⟨address, _, equal⟩ := List.mem_map.mp member
    rw [← equal]
    split_ifs
    · have bound := action_zero_target_plus_one_canonical block.val lane.val
      omega
    · decide

noncomputable section

theorem actual_action_zero_public_target (block : Fin 15) (lane : Fin 16) :
    actualCsrCoefficients (fun _ => 0) (actionInitialTarget block.val lane.val) =
      (actionZeroTarget block.val lane.val : F) := by
  by_cases rate : lane.val < 8
  · simp only [actionInitialTarget, actionZeroTarget, if_pos rate, Nat.cast_zero]
    by_cases excluded : ActionIntentExcluded (block.val * 8 + lane.val)
    · rw [actionIntentWordTarget, if_pos excluded]
      exact (actual_csr_zero_one _).1
    · rw [actionIntentWordTarget, if_neg excluded]
      exact actual_csr_node_field_equation _
        (action_intent_public_node ⟨block.val * 8 + lane.val, by omega⟩)
  · simp only [actionInitialTarget, actionZeroTarget, if_neg rate]
    have address : lane.val = 8 + (lane.val - 8) := by omega
    rw [address]
    exact actual_action_capacity_coefficient _ block ⟨lane.val - 8, by omega⟩

theorem actual_action_control_residual (block : Fin 15) (lane : Fin 16) (delta : Nat) :
    actualCsrResidual (fun _ => 0) (actionControlPacked block.val lane.val delta)
      (actionInitialAttempt block.val lane.val) = (delta : F) := by
  have addresses := action_control_addresses block lane
  rw [actual_action_residual_formula,
    action_control_readback _ _ _ ⟨hashInitialIndex (79 + block.val) lane.val, addresses.1⟩,
    if_pos rfl,
    action_control_readback _ _ _ ⟨hashFinalIndex (79 + block.val - 1) lane.val, addresses.2.1⟩,
    if_neg addresses.2.2, actual_action_zero_public_target]
  simp only [Nat.cast_zero, ite_self, Nat.cast_add]
  ring

theorem actual_action_all_240_positive_control (offset : Fin 240) :
    ∃ entry, exactCsrAttempts[18468 + offset.val]? = some entry ∧
      actualCsrResidual (fun _ => 0)
        (actionControlPacked (offset.val / 16) (offset.val % 16) 0) entry = 0 := by
  exact ⟨actionInitialAttempt (offset.val / 16) (offset.val % 16), exact_action_all_240_lookup offset,
    actual_action_control_residual ⟨offset.val / 16, by omega⟩ ⟨offset.val % 16, by omega⟩ 0⟩

theorem actual_action_all_240_nonzero_control (offset : Fin 240) :
    ∃ entry, exactCsrAttempts[18468 + offset.val]? = some entry ∧
      actualCsrResidual (fun _ => 0)
        (actionControlPacked (offset.val / 16) (offset.val % 16) 1) entry = 1 ∧
      actualCsrResidual (fun _ => 0)
        (actionControlPacked (offset.val / 16) (offset.val % 16) 1) entry ≠ 0 := by
  refine ⟨actionInitialAttempt (offset.val / 16) (offset.val % 16), exact_action_all_240_lookup offset, ?_, ?_⟩
  · exact actual_action_control_residual ⟨offset.val / 16, by omega⟩ ⟨offset.val % 16, by omega⟩ 1
  · rw [actual_action_control_residual ⟨offset.val / 16, by omega⟩ ⟨offset.val % 16, by omega⟩ 1]
    decide

theorem action_initial_endpoint_metadata :
    actionInitialAttempt 0 0 = attempt 18468 24 0 0 [(29775, 1)] 4 ∧
    actionInitialAttempt 0 8 = attempt 18476 24 8 0 [(30287, 1)] 546 ∧
    actionInitialAttempt 14 11 = attempt 18703 24 235 0 [(30493, 1), (41116, 158)] 1 ∧
    actionInitialAttempt 14 15 = attempt 18707 24 239 0 [(30749, 1), (41372, 158)] 0 := by decide

end
end HegemonCrypto.SmallWood.V8Smz9SourceActionIntentInitial
