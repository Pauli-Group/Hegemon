import SmzaRp05NullifierSourceCsrBase

/-! Import-light block-zero readback for lanes 0–6.  Lanes 0–4 have one
key-row source term; lanes 5–6 have an empty source tail. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NullifierSource

open _root_.Hegemon.Transaction.Poseidon2V8RelationProgram
open _root_.Hegemon.Transaction.Poseidon2V8SemanticSpecification
open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex)
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open _root_.HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
open _root_.Hegemon.Transaction
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 4000000

private theorem csr_singleton_value (values packed : List Nat)
    (index node : Nat) :
    csrFieldSum values packed [(index, node)] =
      (values.getD node 0 : Goldilocks) * (packed.getD index 0 : Goldilocks) := by
  simp [csrFieldSum]

private theorem add_neg_zero_extract {a b : Goldilocks}
    (h : a + -b = 0) : a = b := by
  calc
    a = (a + -b) + b := by simp [add_assoc]
    _ = b := by rw [h, zero_add]

private theorem first_frame_low_value (inputs : List Nat) (lane : Nat)
    (bound : lane < 8) :
    (firstFrame inputs).getD lane 0 =
      _root_.Hegemon.Transaction.Poseidon2Width16Kernel.fieldAdd 0
        (inputs.getD lane 0) := by
  unfold firstFrame
  have laneBound : lane < 16 := by omega
  rw [List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range laneBound, Option.map_some, Option.getD_some]
  simp [bound]

set_option linter.unusedSimpArgs false in
private theorem nullifier_preimage_low_value (packed : List Nat)
    (input : Fin 2) (lane : Nat) (bound : lane < 8) :
    (nullifierPreimage packed input).getD lane 0 =
      (if lane < 5 then
        packed.getD (inputNullifierKeyRow input * 64 + lane) 0
      else if lane = 7 then projectPosition packed input.val else 0) := by
  interval_cases lane <;>
    simp [nullifierPreimage, inputNullifierKeyRow,
      List.getD_append, List.getD_append_right,
      List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range]

private theorem first_frame_low_source (packed : List Nat) (input : Fin 2)
    (lane : Nat) (laneBound : lane < 7) :
    (firstFrame (nullifierPreimage packed input)).getD lane 0 =
      (if lane < 5 then
        (packed.getD (inputNullifierKeyRow input * 64 + lane) 0 : Goldilocks)
      else 0) := by
  rw [first_frame_low_value _ _ (by omega), nullifier_preimage_low_value _ _ _ (by omega)]
  by_cases hKey : lane < 5
  · rw [V8Smz9Poseidon2TemplateRefinement.cast_fieldAdd]
    simp [hKey]
  · have hZero : lane = 5 ∨ lane = 6 := by omega
    rcases hZero with h | h <;>
      rw [V8Smz9Poseidon2TemplateRefinement.cast_fieldAdd] <;> simp [h]

theorem accepted_block0_lanes0to6_readback_both_inputs
    (values packed : List Nat) (input : Fin 2) (lane : Fin 16)
    (oneNode negativeNode positiveNode : Nat)
    (powerNode : Nat → Nat) (constantNode : InitialCell → Nat)
    (equation : csrFieldSum values packed
      (initialTerms oneNode negativeNode positiveNode powerNode
        (input, (0 : Fin 2), lane)) =
        (values.getD (constantNode (input, (0 : Fin 2), lane)) 0 : Goldilocks))
    (one : (values.getD oneNode 0 : Goldilocks) = 1)
    (negative : (values.getD negativeNode 0 : Goldilocks) = -1)
    (constant :
      (values.getD (constantNode (input, (0 : Fin 2), lane)) 0 : Goldilocks) =
        (initialConstant (input, (0 : Fin 2), lane) : Goldilocks))
    (laneBound : lane.val < 7) :
    (packed.getD
        (hashInitialIndex (callOf (input, (0 : Fin 2), lane)) lane.val) 0 : Goldilocks) =
      ((firstFrame (nullifierPreimage packed input)).getD lane.val 0 : Goldilocks) := by
  have hConst :
      (values.getD (constantNode (input, (0 : Fin 2), lane)) 0 : Goldilocks) = 0 := by
    have h8 : lane.val ≠ 8 := by omega
    have h9 : lane.val ≠ 9 := by omega
    have h10 : lane.val ≠ 10 := by omega
    have h15 : lane.val ≠ 15 := by omega
    simpa [initialConstant, h8, h9, h10, h15] using constant
  have hHead : csrFieldSum values packed
      [(hashInitialIndex (callOf (input, (0 : Fin 2), lane)) lane.val, oneNode)] =
      (values.getD oneNode 0 : Goldilocks) *
        (packed.getD
          (hashInitialIndex (callOf (input, (0 : Fin 2), lane)) lane.val) 0 : Goldilocks) :=
    csr_singleton_value values packed _ _
  by_cases keyLane : lane.val < 5
  · have hSource :
        initialTerms oneNode negativeNode positiveNode powerNode
            (input, (0 : Fin 2), lane) =
          [(hashInitialIndex (callOf (input, (0 : Fin 2), lane)) lane.val, oneNode)] ++
          [(inputNullifierKeyRow input * 64 + lane.val, negativeNode)] := by
      have laneLT8 : lane.val < 8 := by omega
      simp [initialTerms, callOf, nullifierFirstCall, keyLane, laneLT8]
    have hTail : csrFieldSum values packed
        [(inputNullifierKeyRow input * 64 + lane.val, negativeNode)] =
        (values.getD negativeNode 0 : Goldilocks) *
          (packed.getD (inputNullifierKeyRow input * 64 + lane.val) 0 : Goldilocks) :=
      csr_singleton_value values packed _ _
    have rowEquation := equation
    rw [hSource, csr_sum_append, hHead, hTail, one, negative, hConst] at rowEquation
    have keyReadback :
        (packed.getD
          (hashInitialIndex (callOf (input, (0 : Fin 2), lane)) lane.val) 0 : Goldilocks) =
          (packed.getD (inputNullifierKeyRow input * 64 + lane.val) 0 : Goldilocks) :=
      add_neg_zero_extract (by simpa using rowEquation)
    rw [first_frame_low_source packed input lane.val laneBound, if_pos keyLane]
    exact keyReadback
  · have hEmpty :
        initialTerms oneNode negativeNode positiveNode powerNode
            (input, (0 : Fin 2), lane) =
          [(hashInitialIndex (callOf (input, (0 : Fin 2), lane)) lane.val, oneNode)] := by
      have laneGE : 5 ≤ lane.val := by omega
      have laneLT8 : lane.val < 8 := by omega
      have laneSeven : lane.val ≠ 7 := by omega
      simp [initialTerms, callOf, nullifierFirstCall, laneGE, laneLT8, laneSeven]
    have rowEquation := equation
    rw [hEmpty, hHead, one, hConst] at rowEquation
    have zeroReadback :
        (packed.getD
          (hashInitialIndex (callOf (input, (0 : Fin 2), lane)) lane.val) 0 : Goldilocks) = 0 :=
      by simpa using rowEquation
    rw [first_frame_low_source packed input lane.val laneBound]
    simp only [if_neg keyLane]
    rw [zeroReadback]

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
