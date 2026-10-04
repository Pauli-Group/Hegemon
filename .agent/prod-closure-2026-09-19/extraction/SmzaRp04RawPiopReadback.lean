import SmzaRp04RawRecordedTranscript
import SmzaRawWordReadback

/-! Exact coefficient readback at the PIOP transcript boundary. This is the
mathematical wire encoding used by the extractor, not a Rust refinement. -/
namespace HegemonCrypto.SmallWood.SmzaRp04RawPiopReadback

open SmzaRp04RawRecordedTranscript SmzaRawWordReadback
open V8Smz9HonestWholeViewFinalInput V8Smz9RawCounterCompiler
open V8Smz9EagerPrivacy V8SmzaOracleParser
open HegemonCrypto.CanonicalBytes

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option linter.unusedSimpArgs false

local notation "PiopPrefix" => V8Smz9HonestWholeViewFinalInput.Prefix
attribute [local irreducible] sourceFinalWords

theorem raw_payload_of_frame (input bytes : V8SmzaOracleParser.RawInput)
    (kind : Kind) (parsed : parseFramed input = some (roleName kind, bytes))
    (length : bytes.length = payloadBytes kind) :
    rawPayload input = some ⟨kind, bytes⟩ := by
  simp [rawPayload, parsed, role_roundtrip, length]

theorem raw_piop_payload (commitmentPrefix : PiopPrefix)
    (coefficients : CanonicalCoefficients) :
    rawPayload (rawPiopInput commitmentPrefix coefficients) =
      some ⟨.piop, typedWordPayload (sourceFinalWords commitmentPrefix coefficients)⟩ := by
  have length : (typedWordPayload (sourceFinalWords commitmentPrefix coefficients)).length =
      payloadBytes .piop := by
    rw [typed_word_payload_length, source_final_word_count]
    rfl
  exact raw_payload_of_frame _ _ .piop
    (raw_piop_input_roundtrip commitmentPrefix coefficients) length

theorem source_final_coefficient_word (commitmentPrefix : PiopPrefix)
    (coefficients : CanonicalCoefficients) (index : Fin 3105) :
    (sourceFinalWords commitmentPrefix coefficients)[8 + index.val]? =
      some (fieldWord (alternatingCoefficientEquiv.symm coefficients index)) := by
  unfold sourceFinalWords
  rw [List.getElem?_append_right (by simp only [List.length_ofFn]; omega)]
  simp only [List.length_ofFn, Nat.add_sub_cancel_left, List.getElem?_ofFn,
    dif_pos index.isLt]

theorem raw_piop_coefficient_readback (commitmentPrefix : PiopPrefix)
    (coefficients : CanonicalCoefficients) (index : Fin 3105) :
    toGoldilocks (wordAt (typedWordPayload (sourceFinalWords commitmentPrefix coefficients))
      (8 + index.val)) = alternatingCoefficientEquiv.symm coefficients index := by
  rw [word_at_typed_payload _ _ _
    (source_final_coefficient_word commitmentPrefix coefficients index)]
  exact toGoldilocks_fromGoldilocks _

theorem raw_piop_all_coefficients_readback (commitmentPrefix : PiopPrefix)
    (coefficients : CanonicalCoefficients) :
    alternatingCoefficientEquiv (fun index => toGoldilocks
      (wordAt (typedWordPayload (sourceFinalWords commitmentPrefix coefficients))
        (8 + index.val))) = coefficients := by
  have coordinates : (fun index : Fin 3105 => toGoldilocks
      (wordAt (typedWordPayload (sourceFinalWords commitmentPrefix coefficients))
        (8 + index.val))) = alternatingCoefficientEquiv.symm coefficients := by
    funext index
    exact raw_piop_coefficient_readback commitmentPrefix coefficients index
  rw [coordinates, Equiv.apply_symm_apply]

end
end HegemonCrypto.SmallWood.SmzaRp04RawPiopReadback
