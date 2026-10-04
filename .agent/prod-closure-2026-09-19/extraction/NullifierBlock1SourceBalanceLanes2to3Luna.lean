import NullifierBlock1SourceBalanceSplitLuna

/-! Exact block-one rho source equations for lanes 2 and 3.  These generic
input lemmas cover the four concrete (input,lane) cells without enumerating
all inputs or lanes. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NullifierSource

open _root_.Hegemon.Transaction.Poseidon2V8RelationProgram
open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex hashFinalIndex)
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open _root_.Hegemon.Transaction
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 4000000

private theorem neg_add_eq_neg_sub (a b : Goldilocks) :
    -a + b = -(a - b) := by ring

private theorem packed_sub_cast (packed : List Nat) (firstCall lane : Nat)
    (packedCanonical : ∀ index, packed.getD index 0 < fieldModulus) :
    ((fieldSub (packed.getD (hashInitialIndex (firstCall + 1) lane) 0)
      (packed.getD (hashFinalIndex firstCall lane) 0) : Nat) : Goldilocks) =
      (packed.getD (hashInitialIndex (firstCall + 1) lane) 0 : Goldilocks) -
        (packed.getD (hashFinalIndex firstCall lane) 0 : Goldilocks) := by
  apply field_sub_cast
  have right := packedCanonical (hashFinalIndex firstCall lane)
  unfold fieldModulus at right ⊢
  omega

private theorem nullifier_preimage_rho2_getD (packed : List Nat)
    (input : Fin 2) :
    (nullifierPreimage packed input).getD 10 0 =
      spongeSourceWord packed (inputNoteFirstCall input) 8 := by
  change (((List.range 5).map (fun limb =>
      packed.getD (inputNullifierKeyRow input * 64 + limb) 0) ++
      [0, 0, projectPosition packed input.val]) ++
      (List.range 4).map (fun limb =>
        spongeSourceWord packed (inputNoteFirstCall input) (6 + limb))).getD 10 0 = _
  rw [List.getD_append_right _ _ _ _ (by simp :
    (((List.range 5).map (fun limb =>
      packed.getD (inputNullifierKeyRow input * 64 + limb) 0) ++
      [0, 0, projectPosition packed input.val]).length ≤ 10))]
  change ((List.range 4).map (fun limb =>
    spongeSourceWord packed (inputNoteFirstCall input) (6 + limb))).getD 2 0 = _
  rw [List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range (by decide : 2 < 4), Option.map_some,
    Option.getD_some]

private theorem nullifier_preimage_rho3_getD (packed : List Nat)
    (input : Fin 2) :
    (nullifierPreimage packed input).getD 11 0 =
      spongeSourceWord packed (inputNoteFirstCall input) 9 := by
  change (((List.range 5).map (fun limb =>
      packed.getD (inputNullifierKeyRow input * 64 + limb) 0) ++
      [0, 0, projectPosition packed input.val]) ++
      (List.range 4).map (fun limb =>
        spongeSourceWord packed (inputNoteFirstCall input) (6 + limb))).getD 11 0 = _
  rw [List.getD_append_right _ _ _ _ (by simp :
    (((List.range 5).map (fun limb =>
      packed.getD (inputNullifierKeyRow input * 64 + limb) 0) ++
      [0, 0, projectPosition packed input.val]).length ≤ 11))]
  change ((List.range 4).map (fun limb =>
    spongeSourceWord packed (inputNoteFirstCall input) (6 + limb))).getD 3 0 = _
  rw [List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range (by decide : 3 < 4), Option.map_some,
    Option.getD_some]

private theorem sponge_source_rho2 (packed : List Nat) (input : Fin 2) :
    spongeSourceWord packed (inputNoteFirstCall input) 8 =
      fieldSub (packed.getD
        (hashInitialIndex (inputNoteFirstCall input + 1) 0) 0)
        (packed.getD
          (hashFinalIndex (inputNoteFirstCall input) 0) 0) := by
  simp [spongeSourceWord, packedWord]

private theorem sponge_source_rho3 (packed : List Nat) (input : Fin 2) :
    spongeSourceWord packed (inputNoteFirstCall input) 9 =
      fieldSub (packed.getD
        (hashInitialIndex (inputNoteFirstCall input + 1) 1) 0)
        (packed.getD
          (hashFinalIndex (inputNoteFirstCall input) 1) 0) := by
  simp [spongeSourceWord, packedWord]

private theorem block1_source_sum_lane2 (values packed : List Nat)
    (input : Fin 2) (negativeNode positiveNode : Nat)
    (negative : (values.getD negativeNode 0 : Goldilocks) = -1)
    (positive : (values.getD positiveNode 0 : Goldilocks) = 1) :
    csrFieldSum values packed
      (block1SourceTerms negativeNode positiveNode input 2) =
      -((packed.getD
          (hashInitialIndex (inputNoteFirstCall input + 1) 0) 0 : Goldilocks) -
        (packed.getD
          (hashFinalIndex (inputNoteFirstCall input) 0) 0 : Goldilocks)) := by
  have hTerms : block1SourceTerms negativeNode positiveNode input 2 =
      [(hashInitialIndex (inputNoteFirstCall input + 1) 0, negativeNode),
        (hashFinalIndex (inputNoteFirstCall input) 0, positiveNode)] := by
    simp [block1SourceTerms]
  rw [hTerms]
  simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
    List.sum_nil, negative, positive, one_mul, neg_one_mul]
  simpa only [add_zero] using neg_add_eq_neg_sub
    (packed.getD (hashInitialIndex (inputNoteFirstCall input + 1) 0) 0 : Goldilocks)
    (packed.getD (hashFinalIndex (inputNoteFirstCall input) 0) 0 : Goldilocks)

private theorem block1_source_sum_lane3 (values packed : List Nat)
    (input : Fin 2) (negativeNode positiveNode : Nat)
    (negative : (values.getD negativeNode 0 : Goldilocks) = -1)
    (positive : (values.getD positiveNode 0 : Goldilocks) = 1) :
    csrFieldSum values packed
      (block1SourceTerms negativeNode positiveNode input 3) =
      -((packed.getD
          (hashInitialIndex (inputNoteFirstCall input + 1) 1) 0 : Goldilocks) -
        (packed.getD
          (hashFinalIndex (inputNoteFirstCall input) 1) 0 : Goldilocks)) := by
  have hTerms : block1SourceTerms negativeNode positiveNode input 3 =
      [(hashInitialIndex (inputNoteFirstCall input + 1) 1, negativeNode),
        (hashFinalIndex (inputNoteFirstCall input) 1, positiveNode)] := by
    simp [block1SourceTerms]
  rw [hTerms]
  simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
    List.sum_nil, negative, positive, one_mul, neg_one_mul]
  simpa only [add_zero] using neg_add_eq_neg_sub
    (packed.getD (hashInitialIndex (inputNoteFirstCall input + 1) 1) 0 : Goldilocks)
    (packed.getD (hashFinalIndex (inputNoteFirstCall input) 1) 0 : Goldilocks)

theorem block1_source_balance_lane2_both_inputs
    (values packed : List Nat) (input : Fin 2)
    (negativeNode positiveNode : Nat)
    (negative : (values.getD negativeNode 0 : Goldilocks) = -1)
    (positive : (values.getD positiveNode 0 : Goldilocks) = 1)
    (packedCanonical : ∀ index, packed.getD index 0 < fieldModulus) :
    csrFieldSum values packed
      (block1SourceTerms negativeNode positiveNode input 2) =
      -((nullifierPreimage packed input).getD 10 0 : Goldilocks) := by
  have subCast := packed_sub_cast packed (inputNoteFirstCall input) 0 packedCanonical
  calc
    csrFieldSum values packed (block1SourceTerms negativeNode positiveNode input 2) =
        -((packed.getD (hashInitialIndex (inputNoteFirstCall input + 1) 0) 0 : Goldilocks) -
          (packed.getD (hashFinalIndex (inputNoteFirstCall input) 0) 0 : Goldilocks)) :=
      block1_source_sum_lane2 values packed input negativeNode positiveNode negative positive
    _ = -((fieldSub
          (packed.getD (hashInitialIndex (inputNoteFirstCall input + 1) 0) 0)
          (packed.getD (hashFinalIndex (inputNoteFirstCall input) 0) 0) : Nat) : Goldilocks) := by
      rw [subCast]
    _ = -((nullifierPreimage packed input).getD 10 0 : Goldilocks) := by
      have hRho : (nullifierPreimage packed input).getD 10 0 =
          fieldSub (packed.getD
            (hashInitialIndex (inputNoteFirstCall input + 1) 0) 0)
            (packed.getD
              (hashFinalIndex (inputNoteFirstCall input) 0) 0) := by
        rw [nullifier_preimage_rho2_getD, sponge_source_rho2]
      exact congrArg (fun x : Goldilocks => -x)
        (congrArg (fun x : Nat => (x : Goldilocks)) hRho.symm)

theorem block1_source_balance_lane3_both_inputs
    (values packed : List Nat) (input : Fin 2)
    (negativeNode positiveNode : Nat)
    (negative : (values.getD negativeNode 0 : Goldilocks) = -1)
    (positive : (values.getD positiveNode 0 : Goldilocks) = 1)
    (packedCanonical : ∀ index, packed.getD index 0 < fieldModulus) :
    csrFieldSum values packed
      (block1SourceTerms negativeNode positiveNode input 3) =
      -((nullifierPreimage packed input).getD 11 0 : Goldilocks) := by
  have subCast := packed_sub_cast packed (inputNoteFirstCall input) 1 packedCanonical
  calc
    csrFieldSum values packed (block1SourceTerms negativeNode positiveNode input 3) =
        -((packed.getD (hashInitialIndex (inputNoteFirstCall input + 1) 1) 0 : Goldilocks) -
          (packed.getD (hashFinalIndex (inputNoteFirstCall input) 1) 0 : Goldilocks)) :=
      block1_source_sum_lane3 values packed input negativeNode positiveNode negative positive
    _ = -((fieldSub
          (packed.getD (hashInitialIndex (inputNoteFirstCall input + 1) 1) 0)
          (packed.getD (hashFinalIndex (inputNoteFirstCall input) 1) 0) : Nat) : Goldilocks) := by
      rw [subCast]
    _ = -((nullifierPreimage packed input).getD 11 0 : Goldilocks) := by
      have hRho : (nullifierPreimage packed input).getD 11 0 =
          fieldSub (packed.getD
            (hashInitialIndex (inputNoteFirstCall input + 1) 1) 0)
            (packed.getD
              (hashFinalIndex (inputNoteFirstCall input) 1) 0) := by
        rw [nullifier_preimage_rho3_getD, sponge_source_rho3]
      exact congrArg (fun x : Goldilocks => -x)
        (congrArg (fun x : Nat => (x : Goldilocks)) hRho.symm)

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
