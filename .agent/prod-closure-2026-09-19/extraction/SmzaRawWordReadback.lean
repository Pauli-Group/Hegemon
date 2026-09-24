import SmallWoodV8SmzaOracleParserR2
import HegemonCrypto.SmallWoodV8Smz9RawCounterCompiler

/-! Word-level readback of the exact canonical transcript encoding. These
lemmas concern the protocol encoding, not a compiler or universal Rust model. -/
namespace HegemonCrypto.SmallWood.SmzaRawWordReadback

open HegemonCrypto.CanonicalBytes V8Smz9RawCounterCompiler
noncomputable section
set_option autoImplicit false

theorem typed_payload_drop_word (word : Fin (2 ^ 64))
    (words : List (Fin (2 ^ 64))) :
    (typedWordPayload (word :: words)).drop 8 = typedWordPayload words := by
  simpa only [typedWordPayload, encodeLE_length] using
    (List.drop_left (l₁ := encodeLE 8 word.val) (l₂ := typedWordPayload words))

theorem typed_payload_take_word (word : Fin (2 ^ 64))
    (words : List (Fin (2 ^ 64))) :
    (typedWordPayload (word :: words)).take 8 = encodeLE 8 word.val := by
  simpa only [typedWordPayload, encodeLE_length] using
    (List.take_left (l₁ := encodeLE 8 word.val) (l₂ := typedWordPayload words))

theorem typed_payload_drop_words (words : List (Fin (2 ^ 64))) (count : Nat) :
    (typedWordPayload words).drop (8 * count) = typedWordPayload (words.drop count) := by
  induction count generalizing words with
  | zero => simp
  | succ count ih =>
      cases words with
      | nil => simp [typedWordPayload]
      | cons word words =>
          rw [show 8 * (count + 1) = 8 + 8 * count by omega,
            ← List.drop_drop, typed_payload_drop_word]
          exact ih words

theorem word_at_typed_payload (words : List (Fin (2 ^ 64)))
    (index : Nat) (word : Fin (2 ^ 64)) (found : words[index]? = some word) :
    V8SmzaOracleParser.wordAt (typedWordPayload words) index = word.val := by
  have dropped : ∃ rest, words.drop index = word :: rest := by
    obtain ⟨bound, same⟩ := List.getElem?_eq_some_iff.mp found
    exact ⟨words.drop (index + 1), (List.drop_eq_getElem_cons bound).trans
      (congrArg (fun value => value :: words.drop (index + 1)) same)⟩
  obtain ⟨rest, dropped⟩ := dropped
  unfold V8SmzaOracleParser.wordAt V8Smz9CoherentMerkleGeometry.wordAt
  rw [typed_payload_drop_words, dropped, typed_payload_take_word, decodeLE_encodeLE]
  exact Nat.mod_eq_of_lt word.isLt

end
end HegemonCrypto.SmallWood.SmzaRawWordReadback
