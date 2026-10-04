import NullifierBlock1LastFrameLuna

/-! Tiny source-balance cases: empty lanes 4--15 and direct note lanes 0--1. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NullifierSource

open _root_.Hegemon.Transaction.Poseidon2V8RelationProgram
open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex)
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open _root_.Hegemon.Transaction
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option linter.unusedSimpArgs false
set_option maxRecDepth 100000
set_option maxHeartbeats 4000000

/-- In lanes 4--15 the block-one source tail is empty, and the frame delta
is zero. -/
theorem block1_source_balance_lanes4to15
    (values packed : List Nat) (input : Fin 2) (lane : Fin 16)
    (negativeNode positiveNode : Nat) (laneHigh : 4 ≤ lane.val) :
    csrFieldSum values packed
      (block1SourceTerms negativeNode positiveNode input lane.val) =
      -((if lane.val < 4 then
          (nullifierPreimage packed input).getD (8 + lane.val) 0
        else 0 : Nat) : Goldilocks) := by
  have notLow : ¬ lane.val < 4 := by omega
  by_cases highEight : 8 ≤ lane.val
  · simp only [block1SourceTerms, if_pos highEight, csrFieldSum,
      List.map_nil, List.sum_nil, if_neg notLow, Nat.cast_zero, neg_zero]
  · simp only [block1SourceTerms, if_neg highEight, if_neg notLow,
      csrFieldSum, List.map_nil, List.sum_nil, Nat.cast_zero, neg_zero]

private theorem nullifierPreimage_note_word6 (packed : List Nat)
    (input : Fin 2) :
    (nullifierPreimage packed input).getD 8 0 =
      spongeSourceWord packed (inputNoteFirstCall input) 6 := by
  change (((List.range 5).map (fun limb =>
      packed.getD (inputNullifierKeyRow input * 64 + limb) 0) ++
      [0, 0, projectPosition packed input.val]) ++
      (List.range 4).map (fun limb =>
        spongeSourceWord packed (inputNoteFirstCall input) (6 + limb))).getD 8 0 =
      spongeSourceWord packed (inputNoteFirstCall input) 6
  rw [List.getD_append_right _ _ _ _ (by simp :
    (((List.range 5).map (fun limb =>
      packed.getD (inputNullifierKeyRow input * 64 + limb) 0) ++
      [0, 0, projectPosition packed input.val])).length ≤ 8)]
  change ((List.range 4).map (fun limb =>
    spongeSourceWord packed (inputNoteFirstCall input) (6 + limb))).getD 0 0 = _
  rw [List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range (by decide), Option.map_some, Option.getD_some]

private theorem nullifierPreimage_note_word7 (packed : List Nat)
    (input : Fin 2) :
    (nullifierPreimage packed input).getD 9 0 =
      spongeSourceWord packed (inputNoteFirstCall input) 7 := by
  change (((List.range 5).map (fun limb =>
      packed.getD (inputNullifierKeyRow input * 64 + limb) 0) ++
      [0, 0, projectPosition packed input.val]) ++
      (List.range 4).map (fun limb =>
        spongeSourceWord packed (inputNoteFirstCall input) (6 + limb))).getD 9 0 =
      spongeSourceWord packed (inputNoteFirstCall input) 7
  rw [List.getD_append_right _ _ _ _ (by simp :
    (((List.range 5).map (fun limb =>
      packed.getD (inputNullifierKeyRow input * 64 + limb) 0) ++
      [0, 0, projectPosition packed input.val])).length ≤ 9)]
  change ((List.range 4).map (fun limb =>
    spongeSourceWord packed (inputNoteFirstCall input) (6 + limb))).getD 1 0 = _
  rw [List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range (by decide), Option.map_some, Option.getD_some]

private theorem block1_source_balance_lane0
    (values packed : List Nat) (input : Fin 2)
    (negativeNode positiveNode : Nat)
    (negative : (values.getD negativeNode 0 : Goldilocks) = -1) :
    csrFieldSum values packed
      (block1SourceTerms negativeNode positiveNode input 0) =
      -((if (0 : Nat) < 4 then
          (nullifierPreimage packed input).getD (8 + 0) 0
        else 0 : Nat) : Goldilocks) := by
  have shape : block1SourceTerms negativeNode positiveNode input 0 =
      [(hashInitialIndex (inputNoteFirstCall input) 6, negativeNode)] := by
    simp only [block1SourceTerms,
      if_neg (by decide : ¬ (0 : Nat) ≥ 8),
      if_pos (by decide : (0 : Nat) < 4),
      Nat.reduceAdd, Nat.reduceDiv, Nat.reduceMod, Nat.add_zero,
      if_pos (by decide : (6 : Nat) < 8)]
  have wordRead : packed.getD (hashInitialIndex (inputNoteFirstCall input) 6) 0 =
      (nullifierPreimage packed input).getD 8 0 := by
    rw [nullifierPreimage_note_word6]
    simp only [spongeSourceWord, packedWord, Nat.reduceDiv, Nat.reduceMod,
      Nat.add_zero, ↓reduceIte]
  rw [shape]
  simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
  rw [negative, wordRead]
  simp only [neg_one_mul, add_zero,
    if_pos (by decide : (0 : Nat) < 4), Nat.reduceAdd]

private theorem block1_source_balance_lane1
    (values packed : List Nat) (input : Fin 2)
    (negativeNode positiveNode : Nat)
    (negative : (values.getD negativeNode 0 : Goldilocks) = -1) :
    csrFieldSum values packed
      (block1SourceTerms negativeNode positiveNode input 1) =
      -((if (1 : Nat) < 4 then
          (nullifierPreimage packed input).getD (8 + 1) 0
        else 0 : Nat) : Goldilocks) := by
  have shape : block1SourceTerms negativeNode positiveNode input 1 =
      [(hashInitialIndex (inputNoteFirstCall input) 7, negativeNode)] := by
    simp only [block1SourceTerms,
      if_neg (by decide : ¬ (1 : Nat) ≥ 8),
      if_pos (by decide : (1 : Nat) < 4),
      Nat.reduceAdd, Nat.reduceDiv, Nat.reduceMod, Nat.add_zero,
      if_pos (by decide : (7 : Nat) < 8)]
  have wordRead : packed.getD (hashInitialIndex (inputNoteFirstCall input) 7) 0 =
      (nullifierPreimage packed input).getD 9 0 := by
    rw [nullifierPreimage_note_word7]
    simp only [spongeSourceWord, packedWord, Nat.reduceDiv, Nat.reduceMod,
      Nat.add_zero, ↓reduceIte]
  rw [shape]
  simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
  rw [negative, wordRead]
  simp only [neg_one_mul, add_zero,
    if_pos (by decide : (1 : Nat) < 4), Nat.reduceAdd]

/-- The exact direct-read branch for block-one lanes zero and one, without
the subtraction paths for lanes two and three. -/
theorem block1_source_balance_lanes01
    (values packed : List Nat) (input : Fin 2) (lane : Fin 16)
    (negativeNode positiveNode : Nat)
    (negative : (values.getD negativeNode 0 : Goldilocks) = -1)
    (laneLow : lane.val < 2) :
    csrFieldSum values packed
      (block1SourceTerms negativeNode positiveNode input lane.val) =
      -((if lane.val < 4 then
          (nullifierPreimage packed input).getD (8 + lane.val) 0
        else 0 : Nat) : Goldilocks) := by
  have laneCases : lane.val = 0 ∨ lane.val = 1 := by omega
  rcases laneCases with laneZero | laneOne
  · have laneEq : lane = (0 : Fin 16) := Fin.ext laneZero
    subst lane
    simpa using block1_source_balance_lane0
      values packed input negativeNode positiveNode negative
  · have laneEq : lane = (1 : Fin 16) := Fin.ext laneOne
    subst lane
    simpa using block1_source_balance_lane1
      values packed input negativeNode positiveNode negative

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
