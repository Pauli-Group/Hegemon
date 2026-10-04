import HegemonCrypto.SmallWoodV8Smz9HonestRequestSchedule
import HegemonCrypto.SmallWoodV8Smz9CappedRawSampler

/-! Minimal generic source-loop/parser semantics shared by current role
readbacks. This module intentionally has no dependency on the historical
OpeningReadback experiment. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFieldCounterParser

open V8Smz9HonestRequestSchedule
open V8Smz9WholeViewObservation
open V8Smz9RawCounterCompiler
open V8Smz9CappedRawSampler
open V8Smz9CoherentMerkleInstrument
open V8Smz9HiddenLeafQrom

noncomputable section
set_option autoImplicit false

private def allAcceptedWords {Other : Type}
    (oracle : Other → DigestRegister) (accepted : List FieldWord)
    (inputs : List Other) : List FieldWord :=
  accepted ++ (inputs.map fun input => acceptedFieldWords
    (sourceDigestWords (oracle input))).flatten

private theorem accepted_field_words_append (left right : List Nat) :
    acceptedFieldWords (left ++ right) = acceptedFieldWords left ++ acceptedFieldWords right := by
  simp [acceptedFieldWords]

private theorem accepted_field_words_flatten (words : List (List Nat)) :
    acceptedFieldWords words.flatten = (words.map acceptedFieldWords).flatten := by
  induction words with
  | nil => rfl
  | cons head tail ih => simp [accepted_field_words_append, ih]

private theorem interpret_source_field_read_loop {Other : Type}
    (requested : Nat) (accepted : List FieldWord) (inputs : List Other)
    (oracle : Other → DigestRegister) :
    NonleafProgram.interpret oracle (sourceFieldReadLoop requested accepted inputs) =
      if requested ≤ (allAcceptedWords oracle accepted inputs).length then
        some ((allAcceptedWords oracle accepted inputs).take requested) else none := by
  induction inputs generalizing accepted with
  | nil =>
      simp only [allAcceptedWords, List.map_nil, List.flatten_nil, List.append_nil]
      change NonleafProgram.interpret oracle
        (if requested ≤ accepted.length then
          (NonleafProgram.done (some (accepted.take requested)) :
            NonleafProgram Other (Option (List FieldWord)))
          else .done none) = _
      split <;> simp only [NonleafProgram.interpret]
  | cons input rest ih =>
      by_cases enough : requested ≤ accepted.length
      · have enoughAll : requested ≤ (allAcceptedWords oracle accepted (input :: rest)).length := by
          unfold allAcceptedWords
          simp only [List.length_append]
          omega
        change NonleafProgram.interpret oracle
          (if requested ≤ accepted.length then
            (NonleafProgram.done (some (accepted.take requested)) :
              NonleafProgram Other (Option (List FieldWord)))
            else .read input (fun digest => sourceFieldReadLoop requested
              (accepted ++ acceptedFieldWords (sourceDigestWords digest)) rest)) = _
        rw [if_pos enough]
        simp only [NonleafProgram.interpret]
        rw [if_pos enoughAll]
        unfold allAcceptedWords
        simp only [List.take_append_of_le_length enough]
      · simp only [sourceFieldReadLoop, enough, ↓reduceIte, NonleafProgram.interpret]
        rw [ih]
        simp [allAcceptedWords, List.append_assoc]

theorem source_digest_of_raw_bits (digest : DigestRegister) :
    sourceDigestOfByteBlock (rawDigestBits.symm digest) = sourceDigest digest := by
  rfl

theorem source_field_loop_is_counter_parser {Other : Type} {blocks : Nat}
    (requested : Nat) (keys : Fin blocks → Other)
    (oracle : Other → DigestRegister) :
    NonleafProgram.interpret oracle (sourceFieldReadLoop requested [] (List.ofFn keys)) =
      parseCounterVector requested (fun counter => sourceDigest (oracle (keys counter))) := by
  rw [interpret_source_field_read_loop]
  unfold parseCounterVector counterVectorCandidates allAcceptedWords
  simp only [List.nil_append]
  rw [accepted_field_words_flatten]
  simp only [List.map_ofFn, sourceDigestWords]
  rfl

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentFieldCounterParser
