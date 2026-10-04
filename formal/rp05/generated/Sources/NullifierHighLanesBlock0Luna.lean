import SmzaRp05NullifierSourceCsrBase

/-! Symbolic block-zero high-lane equations: empty source branch, one hash head. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NullifierSource

open _root_.Hegemon.Transaction.Poseidon2V8RelationProgram
open _root_.Hegemon.Transaction.Poseidon2V8SemanticSpecification
open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex)
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open _root_.HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open _root_.HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
open _root_.Hegemon.Transaction
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 4000000

private theorem firstFrame_getD_at_local (inputs : List Nat) (lane : Nat)
    (bound : lane < 16) :
    (firstFrame inputs).getD lane 0 =
      (if lane < 8 then
        Hegemon.Transaction.Poseidon2Width16Kernel.fieldAdd 0 (inputs.getD lane 0)
      else if lane = 8 then currentNullifierDomain
      else if lane = 9 then 12
      else if lane = 10 then poseidon2V8SpongeModeMarker
      else if lane = 15 then poseidon2V8SuiteMarker else 0) := by
  unfold firstFrame
  rw [List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range bound, Option.map_some, Option.getD_some]

/-- All block-zero lanes eight through fifteen have an empty source tail.
The input and lane remain symbolic, and the conclusion is the exact first
frame readback. -/
theorem accepted_block0_high_lane_frame_readback
    (values packed : List Nat) (input : Fin 2) (lane : Fin 16)
    (oneNode negativeNode positiveNode : Nat)
    (powerNode : Nat → Nat) (constantNode : InitialCell → Nat)
    (laneHigh : 8 ≤ lane.val)
    (equation : csrFieldSum values packed
      (initialTerms oneNode negativeNode positiveNode powerNode
        (input, (0 : Fin 2), lane)) =
        (values.getD (constantNode (input, (0 : Fin 2), lane)) 0 : Goldilocks))
    (one : (values.getD oneNode 0 : Goldilocks) = 1)
    (constant :
      (values.getD (constantNode (input, (0 : Fin 2), lane)) 0 : Goldilocks) =
        (initialConstant (input, (0 : Fin 2), lane) : Goldilocks)) :
    (packed.getD
        (hashInitialIndex (callOf (input, (0 : Fin 2), lane)) lane.val) 0 : Goldilocks) =
      ((firstFrame (nullifierPreimage packed input)).getD lane.val 0 : Goldilocks) := by
  let cell : InitialCell := (input, (0 : Fin 2), lane)
  have shape : initialTerms oneNode negativeNode positiveNode powerNode cell =
      [(hashInitialIndex (callOf cell) lane.val, oneNode)] := by
    simp [cell, initialTerms, laneHigh]
  have headSum :
      csrFieldSum values packed
          [(hashInitialIndex (callOf cell) lane.val, oneNode)] =
        (values.getD oneNode 0 : Goldilocks) *
          (packed.getD (hashInitialIndex (callOf cell) lane.val) 0 : Goldilocks) := by
    simp [csrFieldSum]
  have rowEquation := equation
  rw [show (input, (0 : Fin 2), lane) = cell by rfl] at rowEquation
  rw [shape, headSum, one] at rowEquation
  have packedValue :
      (packed.getD (hashInitialIndex (callOf cell) lane.val) 0 : Goldilocks) =
        (initialConstant cell : Goldilocks) := by
    simpa only [one_mul] using rowEquation.trans constant
  have frameValue :
      (firstFrame (nullifierPreimage packed input)).getD lane.val 0 =
        initialConstant cell := by
    rw [firstFrame_getD_at_local _ _ lane.isLt]
    have notLow : ¬ lane.val < 8 := by omega
    simp [cell, initialConstant, notLow]
  change (packed.getD
      (hashInitialIndex (callOf (input, (0 : Fin 2), lane)) lane.val) 0 : Goldilocks) =
    ((firstFrame (nullifierPreimage packed input)).getD lane.val 0 : Goldilocks)
  rw [show (input, (0 : Fin 2), lane) = cell by rfl]
  rw [frameValue]
  exact packedValue

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
