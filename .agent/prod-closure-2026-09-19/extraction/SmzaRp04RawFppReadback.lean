import SmzaRp04RawPiopReadback

/-! FPP coefficient readback keeps the existing trailing context binding.
The mathematical byte boundary is local to this transcript, not a universal
implementation/refinement claim. -/
namespace HegemonCrypto.SmallWood.SmzaRp04RawFppReadback

open SmzaRawWordReadback SmzaRp04RawPiopReadback
open V8Smz9HonestWholeViewFinalInput V8Smz9RawCounterCompiler
open V8Smz9EagerPrivacy V8SmzaOracleParser

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option linter.unusedSimpArgs false

theorem word_at_prefix_append (leading suffix : List Byte) (index : Nat)
    (enough : 8 * (index + 1) ≤ leading.length) :
    wordAt (leading ++ suffix) index = wordAt leading index := by
  unfold wordAt V8Smz9CoherentMerkleGeometry.wordAt
  rw [List.drop_append_of_le_length (by omega),
    List.take_append_of_le_length (by rw [List.length_drop]; omega)]

theorem word_at_typed_payload_append (words : List (Fin (2 ^ 64)))
    (suffix : List Byte) (index : Nat) (word : Fin (2 ^ 64))
    (found : words[index]? = some word) :
    wordAt (typedWordPayload words ++ suffix) index = word.val := by
  have bound := (List.getElem?_eq_some_iff.mp found).1
  rw [word_at_prefix_append _ _ _ (by rw [typed_word_payload_length]; omega)]
  exact word_at_typed_payload words index word found

abbrev FppCoefficients := Fin 5 → Fin 406 → Goldilocks

def sourceFppWords (commitmentPrefix : Prefix) (coefficients : FppCoefficients) :
    List (Fin (2 ^ 64)) :=
  List.ofFn commitmentPrefix ++ List.ofFn fun index : Fin 2030 =>
    let coordinate : Fin 5 × Fin 406 := finProdFinEquiv.symm index
    fieldWord (coefficients coordinate.1 coordinate.2)

theorem source_fpp_word_count (commitmentPrefix : Prefix)
    (coefficients : FppCoefficients) :
    (sourceFppWords commitmentPrefix coefficients).length = 2038 := by
  simp only [sourceFppWords, List.length_append, List.length_ofFn]

attribute [local irreducible] sourceFppWords

def fppPayload (commitmentPrefix : Prefix) (coefficients : FppCoefficients)
    (binding : List Byte) : List Byte :=
  typedWordPayload (sourceFppWords commitmentPrefix coefficients) ++ binding

theorem fpp_payload_length (commitmentPrefix : Prefix)
    (coefficients : FppCoefficients) (binding : List Byte)
    (bindingLength : binding.length = 1104) :
    (fppPayload commitmentPrefix coefficients binding).length = 17408 := by
  rw [fppPayload, List.length_append, typed_word_payload_length,
    source_fpp_word_count, bindingLength]

theorem source_fpp_coefficient_word (commitmentPrefix : Prefix)
    (coefficients : FppCoefficients) (row : Fin 5) (coefficient : Fin 406) :
    (sourceFppWords commitmentPrefix coefficients)[8 + (finProdFinEquiv (row, coefficient)).val]? =
      some (fieldWord (coefficients row coefficient)) := by
  unfold sourceFppWords
  rw [List.getElem?_append_right (by simp only [List.length_ofFn]; omega)]
  simp only [List.length_ofFn, Nat.add_sub_cancel_left, List.getElem?_ofFn,
    dif_pos (finProdFinEquiv (row, coefficient)).isLt, Equiv.symm_apply_apply]
  change some (fieldWord (coefficients
    (finProdFinEquiv.symm (finProdFinEquiv (row, coefficient))).1
    (finProdFinEquiv.symm (finProdFinEquiv (row, coefficient))).2)) = _
  rw [Equiv.symm_apply_apply]

theorem raw_fpp_coefficient_readback (commitmentPrefix : Prefix)
    (coefficients : FppCoefficients) (binding : List Byte)
    (row : Fin 5) (coefficient : Fin 406) :
    toGoldilocks (wordAt (fppPayload commitmentPrefix coefficients binding)
      (8 + row.val * 406 + coefficient.val)) = coefficients row coefficient := by
  have offset : 8 + row.val * 406 + coefficient.val =
      8 + (finProdFinEquiv (row, coefficient)).val := by
    change 8 + row.val * 406 + coefficient.val =
      8 + (coefficient.val + 406 * row.val)
    omega
  rw [offset, fppPayload, word_at_typed_payload_append _ _ _ _
    (source_fpp_coefficient_word commitmentPrefix coefficients row coefficient)]
  exact toGoldilocks_fromGoldilocks _

def rawFppInput (commitmentPrefix : Prefix) (coefficients : FppCoefficients)
    (binding : List Byte) : V8SmzaOracleParser.RawInput :=
  framedInput (roleName .fpp) (fppPayload commitmentPrefix coefficients binding)

theorem raw_fpp_payload (commitmentPrefix : Prefix)
    (coefficients : FppCoefficients) (binding : List Byte)
    (bindingLength : binding.length = 1104) :
    rawPayload (rawFppInput commitmentPrefix coefficients binding) =
      some ⟨.fpp, fppPayload commitmentPrefix coefficients binding⟩ := by
  apply raw_payload_of_frame
  · apply frame_roundtrip
    · decide
    · rw [fpp_payload_length _ _ _ bindingLength]
      norm_num
    · rw [fpp_payload_length _ _ _ bindingLength]
  · exact fpp_payload_length _ _ _ bindingLength

end
end HegemonCrypto.SmallWood.SmzaRp04RawFppReadback
