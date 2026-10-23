import HegemonCrypto.NativePrivateSpendQ58CurrentLeafInput
import HegemonCrypto.NativePrivateSpendQ58CurrentRowBoundary
import HegemonCrypto.SmallWoodV8Smz9HonestWholeViewFinalInput

/-! The CURRENT final PIOP query, sampled at the programming phase before its
response or final proof is disclosed. Each repetition has75 nonlinear followed
by132 nonconstant linear coordinates. The eight hashFpp limbs are raw u64.
The70-byte SMZD/COMPFF01 profile is literal, not the53-byte RP05 profile.
No claim of entropy conditioned on the later final transcript is made. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentTranscriptInput
open HegemonCrypto.CanonicalBytes
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution
open V8Smz9HiddenLeafQrom V8Smz9RawCounterCompiler V8Smz9MixedMaskCompiler
open NativePrivateSpendQ58CurrentLeafInput
open V8Smz9HonestWholeViewFinalInput (RawWord Prefix fieldWord field_word_injective)
open V8Smz9HonestWholeViewGames (InputSampler)
open scoped Classical ENNReal
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option exponentiation.threshold 1024

abbrev ResponseCoordinates := NativePrivateSpendQ58CurrentRowBoundary.Q

def alternatingCoordinates (response : ResponseCoordinates) : Fin 1035 → Goldilocks :=
  fun index =>
    let pair := (finProdFinEquiv : Fin 5 × Fin 207 ≃ Fin 1035).symm index
    Fin.append (response.1 pair.1) (response.2 pair.1) pair.2

theorem alternating_coordinates_injective : Function.Injective alternatingCoordinates := by
  intro left right same
  apply Prod.ext
  · funext repetition coefficient
    have entry := congrFun same
      (finProdFinEquiv (repetition, Fin.castAdd 132 coefficient))
    simpa [alternatingCoordinates] using entry
  · funext repetition coefficient
    have entry := congrFun same
      (finProdFinEquiv (repetition, Fin.natAdd 75 coefficient))
    simpa [alternatingCoordinates] using entry

def finalWords (hashFpp : Prefix) (response : ResponseCoordinates) : List RawWord :=
  List.ofFn hashFpp ++ List.ofFn fun index : Fin 1035 =>
    fieldWord (alternatingCoordinates response index)

theorem final_word_count (hashFpp : Prefix) (response : ResponseCoordinates) :
    (finalWords hashFpp response).length = 1043 := by
  simp only [finalWords, List.length_append, List.length_ofFn]

theorem final_words_injective (hashFpp : Prefix) : Function.Injective (finalWords hashFpp) := by
  intro left right same
  have coordinates := List.ofFn_injective (List.append_cancel_left same)
  apply alternating_coordinates_injective
  funext index
  exact field_word_injective (congrFun coordinates index)

def framedInput (hashFpp : Prefix) (response : ResponseCoordinates) : List HegemonCrypto.CanonicalBytes.Byte :=
  (encodeLE 8 70 ++ currentProfile ++ encodeLE 8 40 ++
    SmallWoodTranscript.piopTranscriptDomain ++ encodeLE 8 1043) ++
    typedWordPayload (finalWords hashFpp response) ++ encodeLE 8 0

theorem framed_input_length (hashFpp : Prefix) (response : ResponseCoordinates) :
    (framedInput hashFpp response).length = 8486 := by
  have profileLength : currentProfile.length = 70 := by decide
  have roleLength : SmallWoodTranscript.piopTranscriptDomain.length = 40 := by decide
  simp only [framedInput, List.length_append, encodeLE_length,
    typed_word_payload_length, final_word_count, profileLength, roleLength]

theorem framed_input_injective (hashFpp : Prefix) : Function.Injective (framedInput hashFpp) := by
  intro left right same
  have payloads := List.append_cancel_left (List.append_cancel_right same)
  exact final_words_injective hashFpp (typed_word_payload_injective payloads)

def finalKey (bound : Nat) (largeEnough : 8486 ≤ bound)
    (hashFpp : Prefix) (response : ResponseCoordinates) : CurrentOtherRawInput bound :=
  let input := framedInput hashFpp response
  ⟨⟨⟨input.length, Nat.lt_succ_of_le (by rw [framed_input_length]; exact largeEnough)⟩,
    input.get⟩, by
      change input.length ≠ leafBytes
      rw [framed_input_length]
      decide⟩

theorem final_key_literal_bytes (bound : Nat) (largeEnough : 8486 ≤ bound)
    (hashFpp : Prefix) (response : ResponseCoordinates) :
    rawBytes (.inr (finalKey bound largeEnough hashFpp response)) = framedInput hashFpp response :=
  List.ofFn_get _

theorem final_key_injective (bound : Nat) (largeEnough : 8486 ≤ bound) (hashFpp : Prefix) :
    Function.Injective (fun response => (Sum.inr (finalKey bound largeEnough hashFpp response) :
      CurrentFullRawInput bound)) := by
  intro left right same
  apply framed_input_injective hashFpp
  simpa only [final_key_literal_bytes] using congrArg rawBytes same

theorem response_coordinate_count :
    Fintype.card ResponseCoordinates = goldilocksModulus ^ 1035 := by
  simp only [ResponseCoordinates, NativePrivateSpendQ58CurrentRowBoundary.Q,
    NativePrivateSpendQ58ChronologicalMasks.Q, Fintype.card_prod, Fintype.card_fun,
    Fintype.card_fin, goldilocks_card]
  rw [← pow_mul, ← pow_mul, ← pow_add]

/-- Only nine of1035 honest Goldilocks coordinates are needed for this
conservative512-bit lower bound. Eight field words would NOT suffice. -/
theorem coordinate_card_at_least_512 : 2 ^ 512 ≤ Fintype.card ResponseCoordinates := by
  rw [response_coordinate_count]
  have nine : 2 ^ 512 ≤ goldilocksModulus ^ 9 := by norm_num [goldilocksModulus]
  exact nine.trans (pow_le_pow_right₀ (by norm_num [goldilocksModulus]) (by norm_num))

def finalSampler (bound : Nat) (largeEnough : 8486 ≤ bound) (hashFpp : Prefix) :
    InputSampler (CurrentFullRawInput bound) where
  Coins := ResponseCoordinates
  finite := inferInstance
  inhabited := inferInstance
  input := fun response => .inr (finalKey bound largeEnough hashFpp response)

/-- Pointwise in any fixed PRE-PIOP-transcript public prefix/hashFpp reply.
The response coefficients are sampled now, not conditioned on the final proof.
Binding this law to the real request uses the chronological source transport. -/
theorem pre_transcript_input_mass (bound : Nat) (largeEnough : 8486 ≤ bound)
    (hashFpp : Prefix) (input : CurrentFullRawInput bound) :
    pmfMap (uniformFintypePMF (finalSampler bound largeEnough hashFpp).Coins)
      (finalSampler bound largeEnough hashFpp).input input ≤ (2 ^ 512 : ℝ≥0∞)⁻¹ := by
  have exactMass := V8Smz9HonestWholeViewFinalInput.uniform_injective_input_max_mass
    (fun response => (Sum.inr (finalKey bound largeEnough hashFpp response) : CurrentFullRawInput bound))
    (final_key_injective bound largeEnough hashFpp) input
  refine exactMass.trans (ENNReal.inv_le_inv.mpr ?_)
  exact_mod_cast coordinate_card_at_least_512

variable {Work : Type} [Fintype Work]

def transcriptRequest (bound : Nat) (largeEnough : 8486 ≤ bound) (hashFpp : Prefix)
    (next : ResponseCoordinates → DigestRegister → MixedProgram (CurrentFullRawInput bound) Work) :
    MixedProgram (CurrentFullRawInput bound) Work :=
  .freshInput (finalSampler bound largeEnough hashFpp) next

theorem transcript_request_preserves_mass (bound : Nat) (largeEnough : 8486 ≤ bound)
    (hashFpp : Prefix)
    (next : ResponseCoordinates → DigestRegister → MixedProgram (CurrentFullRawInput bound) Work)
    (remaining : ∀ response digest, InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next response digest)) :
    InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (transcriptRequest bound largeEnough hashFpp next) :=
  ⟨pre_transcript_input_mass bound largeEnough hashFpp, remaining⟩

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentTranscriptInput
