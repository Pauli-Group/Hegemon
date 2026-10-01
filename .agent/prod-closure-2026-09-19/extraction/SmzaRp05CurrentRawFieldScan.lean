import SmzaRp05ExecutableChallengeStage
import HegemonCrypto.SmallWoodV8Smz9HonestRequestSchedule

/-! Same-oracle field scan semantics shared by all current challenge roles.
Byte digests are converted to bit registers only at the source-program
boundary; no key schedule or challenge result is assumed here. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentRawFieldScan

open SmzaRp05ExecutableChallengeStage (FieldWord digestWords canonicalWord acceptedWords scan)
open SmzaRp05ExecutableMerkleVerifier (Oracle)
open V8Smz9HonestRequestSchedule (NonleafProgram sourceFieldReadLoop sourceDigestWords sourceDigest)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)
open V8SmzaOracleParser (RawDigest RawInput)

set_option autoImplicit false
noncomputable section

theorem source_digest_words_eq_executed_words (digest : RawDigest) :
    sourceDigestWords (rawDigestBits digest) = digestWords digest := by
  simp only [sourceDigestWords, sourceDigest,
    V8Smz9WholeViewObservation.Sha512Digest.rawWords,
    Equiv.symm_apply_apply, digestWords]
  apply List.map_congr_left
  intro index _
  rw [Nat.mul_comm index 8]

theorem source_accepted_words_eq_executable (digest : RawDigest) :
    V8Smz9RawCounterCompiler.acceptedFieldWords
      (sourceDigestWords (rawDigestBits digest)) = acceptedWords digest := by
  change (sourceDigestWords (rawDigestBits digest)).filterMap canonicalWord =
    (digestWords digest).filterMap canonicalWord
  exact congrArg (List.filterMap canonicalWord)
    (source_digest_words_eq_executed_words digest)

theorem source_field_reader_eq_executable_scan
    {Key : Type} (requested : Nat) (accepted : List FieldWord)
    (inputs : List Key) (keyBytes : Key → RawInput) (oracle : Oracle) :
    NonleafProgram.interpret (fun key => rawDigestBits (oracle (keyBytes key)))
        (sourceFieldReadLoop requested accepted inputs) =
      scan oracle requested accepted (inputs.map keyBytes) := by
  induction inputs generalizing accepted with
  | nil =>
      change NonleafProgram.interpret _
        (if requested ≤ accepted.length then
          (NonleafProgram.done (some (accepted.take requested)) :
            NonleafProgram Key (Option (List FieldWord))) else .done none) =
        if requested ≤ accepted.length then some (accepted.take requested) else none
      split <;> rfl
  | cons key rest ih =>
      change NonleafProgram.interpret _
        (if requested ≤ accepted.length then
          (NonleafProgram.done (some (accepted.take requested)) :
            NonleafProgram Key (Option (List FieldWord))) else
          .read key (fun digest => sourceFieldReadLoop requested
            (List.append (α := FieldWord) accepted
              (V8Smz9RawCounterCompiler.acceptedFieldWords
                (sourceDigestWords digest))) rest)) =
        if requested ≤ accepted.length then some (accepted.take requested) else
          scan oracle requested (accepted ++ acceptedWords (oracle (keyBytes key)))
            (rest.map keyBytes)
      split
      · rfl
      · change NonleafProgram.interpret _
          (sourceFieldReadLoop requested
            (List.append (α := FieldWord) accepted
              (V8Smz9RawCounterCompiler.acceptedFieldWords
                (sourceDigestWords (rawDigestBits (oracle (keyBytes key)))))) rest) = _
        exact (congrArg (fun words : List FieldWord =>
          NonleafProgram.interpret (fun key => rawDigestBits (oracle (keyBytes key)))
            (sourceFieldReadLoop requested (List.append (α := FieldWord) accepted words) rest))
          (source_accepted_words_eq_executable (oracle (keyBytes key)))).trans (ih _)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentRawFieldScan
