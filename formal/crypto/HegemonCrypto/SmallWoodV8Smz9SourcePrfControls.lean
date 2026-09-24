import HegemonCrypto.SmallWoodV8Smz9SourcePrfResiduals

namespace HegemonCrypto.SmallWood.V8Smz9SourcePrfInitial
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointPrf
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000

def prfZeroTarget (lane : Nat) : Nat := if lane < 4 then 0 else prfFrameConstant lane

def prfControlPacked (lane delta : Nat) : List Nat :=
  (List.range 43904).map fun address =>
    if address = hashInitialIndex 0 lane then prfZeroTarget lane + delta else 0

theorem prf_initial_address_bound (lane : Fin 16) : hashInitialIndex 0 lane.val < 43904 := by
  simp only [hashInitialIndex, hashRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, hashRowsPerGroup]
  omega

theorem prf_control_readback (lane delta : Nat) (address : Fin 43904) :
    (prfControlPacked lane delta).getD address.val 0 =
      if address.val = hashInitialIndex 0 lane then prfZeroTarget lane + delta else 0 := by
  simp [prfControlPacked, List.getD_eq_getElem?_getD, address.isLt]

theorem prf_zero_target_plus_one_canonical (lane : Nat) :
    prfZeroTarget lane + 1 < Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus := by
  unfold prfZeroTarget prfFrameConstant
  split_ifs <;> decide

theorem prf_control_canonical (lane : Fin 16) (delta : Fin 2) :
    ExactWords 43904 (prfControlPacked lane.val delta.val) := by
  constructor
  · simp only [prfControlPacked, List.length_map, List.length_range]
  · intro value member
    obtain ⟨address, _, equal⟩ := List.mem_map.mp member
    rw [← equal]
    split_ifs
    · have bound := prf_zero_target_plus_one_canonical lane.val
      omega
    · decide

noncomputable section

theorem actual_prf_zero_public_residual (packed : List Nat) (lane : Fin 16) :
    actualCsrResidual (fun _ => 0) packed (prfInitialAttempt lane.val) =
      (packed.getD (hashInitialIndex 0 lane.val) 0 : F) - (prfZeroTarget lane.val : F) := by
  by_cases rate : lane.val < 4
  · rw [prfInitialAttempt, if_pos rate, actual_prf_rate_residual, prfZeroTarget, if_pos rate]
    simp only [zero_mul, sub_zero, Nat.cast_zero]
  · rw [prfInitialAttempt, if_neg rate, actual_prf_padding_residual, prfZeroTarget, if_neg rate]

theorem actual_prf_control_residual (lane : Fin 16) (delta : Nat) :
    actualCsrResidual (fun _ => 0) (prfControlPacked lane.val delta)
      (prfInitialAttempt lane.val) = (delta : F) := by
  rw [actual_prf_zero_public_residual,
    prf_control_readback _ _ ⟨hashInitialIndex 0 lane.val, prf_initial_address_bound lane⟩,
    if_pos rfl, Nat.cast_add]
  ring

theorem actual_prf_all_16_positive_control (lane : Fin 16) :
    ∃ entry, exactCsrAttempts[15789 + lane.val]? = some entry ∧
      actualCsrResidual (fun _ => 0) (prfControlPacked lane.val 0) entry = 0 :=
  ⟨prfInitialAttempt lane.val, exact_prf_initial_lookup lane, actual_prf_control_residual lane 0⟩

theorem actual_prf_all_16_nonzero_control (lane : Fin 16) :
    ∃ entry, exactCsrAttempts[15789 + lane.val]? = some entry ∧
      actualCsrResidual (fun _ => 0) (prfControlPacked lane.val 1) entry = 1 ∧
      actualCsrResidual (fun _ => 0) (prfControlPacked lane.val 1) entry ≠ 0 := by
  refine ⟨prfInitialAttempt lane.val, exact_prf_initial_lookup lane, actual_prf_control_residual lane 1, ?_⟩
  rw [actual_prf_control_residual]
  decide

theorem prf_initial_endpoint_metadata :
    prfInitialAttempt 0 = attempt 15789 10 0 0 [(18112, 1), (41520, 196), (41524, 197)] 0 ∧
    prfInitialAttempt 3 = attempt 15792 10 3 0 [(18304, 1), (41523, 196), (41527, 197)] 0 ∧
    prfInitialAttempt 4 = attempt 15793 10 4 0 [(18368, 1)] 0 ∧
    prfInitialAttempt 15 = attempt 15804 10 15 0 [(19072, 1)] 544 := by decide

end
end HegemonCrypto.SmallWood.V8Smz9SourcePrfInitial
