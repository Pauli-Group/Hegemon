import SmzaRp04RawPiopReadback

/-! DECS contains evaluations, not coefficients. This boundary preserves the
wire order of 368 head evaluations followed by 38 tail evaluations per
combination. The interpolation order rotates those tails to the front. -/
namespace HegemonCrypto.SmallWood.SmzaRp04RawDecsReadback

open SmzaRawWordReadback SmzaRp04RawPiopReadback
open V8Smz9HonestWholeViewFinalInput V8Smz9RawCounterCompiler
open V8Smz9EagerPrivacy V8SmzaOracleParser

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option linter.unusedSimpArgs false

abbrev WireEvaluations := Fin 12 → Fin 406 → Goldilocks

def sourceDecsWords (commitmentPrefix : Prefix) (evaluations : WireEvaluations) :
    List (Fin (2 ^ 64)) :=
  List.ofFn commitmentPrefix ++ List.ofFn fun index : Fin 4872 =>
    let coordinate : Fin 12 × Fin 406 := finProdFinEquiv.symm index
    fieldWord (evaluations coordinate.1 coordinate.2)

theorem source_decs_word_count (commitmentPrefix : Prefix)
    (evaluations : WireEvaluations) :
    (sourceDecsWords commitmentPrefix evaluations).length = 4880 := by
  simp only [sourceDecsWords, List.length_append, List.length_ofFn]

attribute [local irreducible] sourceDecsWords

def decsPayload (commitmentPrefix : Prefix) (evaluations : WireEvaluations) :
    List Byte := typedWordPayload (sourceDecsWords commitmentPrefix evaluations)

theorem decs_payload_length (commitmentPrefix : Prefix)
    (evaluations : WireEvaluations) :
    (decsPayload commitmentPrefix evaluations).length = 39040 := by
  rw [decsPayload, typed_word_payload_length, source_decs_word_count]

theorem source_decs_evaluation_word (commitmentPrefix : Prefix)
    (evaluations : WireEvaluations) (row : Fin 12) (coordinate : Fin 406) :
    (sourceDecsWords commitmentPrefix evaluations)[8 + (finProdFinEquiv (row, coordinate)).val]? =
      some (fieldWord (evaluations row coordinate)) := by
  unfold sourceDecsWords
  rw [List.getElem?_append_right (by simp only [List.length_ofFn]; omega)]
  simp only [List.length_ofFn, Nat.add_sub_cancel_left, List.getElem?_ofFn,
    dif_pos (finProdFinEquiv (row, coordinate)).isLt, Equiv.symm_apply_apply]
  change some (fieldWord (evaluations
    (finProdFinEquiv.symm (finProdFinEquiv (row, coordinate))).1
    (finProdFinEquiv.symm (finProdFinEquiv (row, coordinate))).2)) = _
  rw [Equiv.symm_apply_apply]

theorem raw_decs_evaluation_readback (commitmentPrefix : Prefix)
    (evaluations : WireEvaluations) (row : Fin 12) (coordinate : Fin 406) :
    toGoldilocks (wordAt (decsPayload commitmentPrefix evaluations)
      (8 + row.val * 406 + coordinate.val)) = evaluations row coordinate := by
  have offset : 8 + row.val * 406 + coordinate.val =
      8 + (finProdFinEquiv (row, coordinate)).val := by
    change 8 + row.val * 406 + coordinate.val =
      8 + (coordinate.val + 406 * row.val)
    omega
  rw [offset, decsPayload, word_at_typed_payload _ _ _
    (source_decs_evaluation_word commitmentPrefix evaluations row coordinate)]
  exact toGoldilocks_fromGoldilocks _

def rotatedCoordinate (index : Fin 406) : Fin 406 :=
  ⟨(index.val + 368) % 406, Nat.mod_lt _ (by decide)⟩

theorem raw_decs_rotated_evaluation_readback (commitmentPrefix : Prefix)
    (evaluations : WireEvaluations) (first : Fin 6) (second : Fin 2)
    (index : Fin 406) :
    toGoldilocks (wordAt (decsPayload commitmentPrefix evaluations)
      (8 + (first.val * 2 + second.val) * 406 + (index.val + 368) % 406)) =
      evaluations (finProdFinEquiv (first, second)) (rotatedCoordinate index) := by
  have rowValue : (finProdFinEquiv (first, second)).val =
      first.val * 2 + second.val := by
    change second.val + 2 * first.val = first.val * 2 + second.val
    omega
  simpa only [rowValue, rotatedCoordinate] using
    raw_decs_evaluation_readback commitmentPrefix evaluations
      (finProdFinEquiv (first, second)) (rotatedCoordinate index)

def rawDecsInput (commitmentPrefix : Prefix) (evaluations : WireEvaluations) :
    V8SmzaOracleParser.RawInput :=
  framedInput (roleName .decs) (decsPayload commitmentPrefix evaluations)

theorem raw_decs_payload (commitmentPrefix : Prefix)
    (evaluations : WireEvaluations) :
    rawPayload (rawDecsInput commitmentPrefix evaluations) =
      some ⟨.decs, decsPayload commitmentPrefix evaluations⟩ := by
  apply raw_payload_of_frame
  · apply frame_roundtrip
    · decide
    · rw [decs_payload_length]
      norm_num
    · rw [decs_payload_length]
  · exact decs_payload_length _ _

end
end HegemonCrypto.SmallWood.SmzaRp04RawDecsReadback
