import NullifierLane7BranchShapeLuna

/-! Compose the symbolic branch and field lemmas with fixed lane-seven reads. -/

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
set_option maxRecDepth 100000
set_option maxHeartbeats 4000000

private theorem firstFrame_getD_seven_local (inputs : List Nat) :
    (firstFrame inputs).getD 7 0 =
      Hegemon.Transaction.Poseidon2Width16Kernel.fieldAdd 0 (inputs.getD 7 0) := by
  unfold firstFrame
  rw [List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range (by decide), Option.map_some, Option.getD_some]
  exact if_pos (by decide : (7 : Nat) < 8)

private theorem nullifierPreimage_getD_seven_local (packed : List Nat)
    (input : Fin 2) :
    (nullifierPreimage packed input).getD 7 0 =
      projectPosition packed input.val := by
  change (((List.range 5).map (fun limb =>
      packed.getD (inputNullifierKeyRow input * 64 + limb) 0) ++
      [0, 0, projectPosition packed input.val]) ++
      (List.range 4).map (fun limb =>
        spongeSourceWord packed (inputNoteFirstCall input) (6 + limb))).getD 7 0 =
      projectPosition packed input.val
  rw [List.getD_append _ _ _ _ (by simp :
    7 < (((List.range 5).map (fun limb =>
      packed.getD (inputNullifierKeyRow input * 64 + limb) 0) ++
      [0, 0, projectPosition packed input.val])).length)]
  rw [List.getD_append_right _ _ _ _ (by simp :
    ((List.range 5).map (fun limb =>
      packed.getD (inputNullifierKeyRow input * 64 + limb) 0)).length ≤ 7)]
  change ([0, 0, projectPosition packed input.val] ++
    (List.range 4).map (fun limb =>
      spongeSourceWord packed (inputNoteFirstCall input) (6 + limb))).getD 2 0 =
    projectPosition packed input.val
  rw [List.getD_append _ _ _ _ (by simp : 2 <
    ([0, 0, projectPosition packed input.val] : List Nat).length)]
  rfl

/-- For arbitrary input, the accepted shaped field row identifies its copied
hash value with the lane-seven value read from the exact first frame. -/
theorem initial_lane7_field_implies_first_frame_readback
    (values packed : List Nat) (input block : Fin 2) (lane : Fin 16)
    (oneNode negativeNode positiveNode : Nat)
    (powerNode : Nat → Nat) (constantNode : InitialCell → Nat)
    (blockZero : block.val = 0) (laneSeven : lane.val = 7)
    (equation : csrFieldSum values packed
      (initialTerms oneNode negativeNode positiveNode powerNode
        (input, block, lane)) =
        (values.getD (constantNode (input, block, lane)) 0 : Goldilocks))
    (one : (values.getD oneNode 0 : Goldilocks) = 1)
    (constantZero :
      (values.getD (constantNode (input, block, lane)) 0 : Goldilocks) = 0)
    (position : csrFieldSum values packed (positionTerms input powerNode) =
      -(projectPosition packed input.val : Goldilocks)) :
    (packed.getD (hashInitialIndex (callOf (input, block, lane)) 7) 0 : Goldilocks) =
      ((firstFrame (nullifierPreimage packed input)).getD 7 0 : Goldilocks) := by
  have shape := initial_terms_block0_lane7_shape
    oneNode negativeNode positiveNode powerNode input block lane blockZero laneSeven
  have field := shaped_csr_head_eq_position values packed (input, block, lane)
    oneNode negativeNode positiveNode powerNode constantNode
    shape equation one constantZero position
  rw [laneSeven] at field
  change (packed.getD
      (hashInitialIndex (callOf (input, block, lane)) 7) 0 : Goldilocks) =
    ((firstFrame (nullifierPreimage packed input)).getD 7 0 : Goldilocks)
  rw [firstFrame_getD_seven_local, nullifierPreimage_getD_seven_local]
  simpa only [V8Smz9Poseidon2TemplateRefinement.cast_fieldAdd,
    Nat.cast_zero, zero_add] using field

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
