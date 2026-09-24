import HegemonCrypto.SmallWoodV8Smz9HonestWholeViewGames
import HegemonCrypto.SmallWoodV8Smz9HonestWholeViewFinalInput

/-! Literal raw-input finite game for the final PIOP hash. All 1407-byte
inputs are the existing LeafInput summand; every other byte string up to an
arbitrary bound is retained in the complement. There is no final-key-only
oracle and no omission of coherent queries mixing roles. The actual 25029-byte
source input is sampled before the independently fresh digest is assigned. -/

namespace HegemonCrypto.SmallWood.V8Smz9HonestFinalGame

open HegemonCrypto.CanonicalBytes
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9HiddenLeafQrom V8Smz9RuntimeDistribution V8Smz9EagerPrivacy
open V8Smz9RawCounterCompiler V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition
open V8Smz9HonestWholeViewGames V8Smz9HonestWholeViewFinalInput
open scoped BigOperators ENNReal Classical

noncomputable section
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

abbrev RawTuple (bound : Nat) := (size : Fin (bound + 1)) × (Fin size.val → CanonicalBytes.Byte)
abbrev OtherRawInput (bound : Nat) := {input : RawTuple bound // input.1.val ≠ 1407}
abbrev FullRawInput (bound : Nat) := LeafInput ⊕ OtherRawInput bound

def rawTupleBytes {bound : Nat} (input : RawTuple bound) : RawInput := List.ofFn input.2

theorem raw_tuple_bytes_injective (bound : Nat) : Function.Injective (@rawTupleBytes bound) := by
  intro left right same
  rcases left with ⟨leftSize, leftBytes⟩
  rcases right with ⟨rightSize, rightBytes⟩
  have lengths := congrArg List.length same
  simp only [rawTupleBytes, List.length_ofFn] at lengths
  have sizeSame : leftSize = rightSize := Fin.ext lengths
  subst rightSize
  have values : leftBytes = rightBytes := List.ofFn_injective same
  subst rightBytes
  rfl

def rawBytes {bound : Nat} : FullRawInput bound → RawInput
  | .inl input => List.ofFn input
  | .inr input => rawTupleBytes input.1

def otherRawKey (bound : Nat) (input : RawInput) (bounded : input.length ≤ bound)
    (notLeafLength : input.length ≠ 1407) : OtherRawInput bound :=
  ⟨⟨⟨input.length, Nat.lt_succ_of_le bounded⟩, input.get⟩, notLeafLength⟩

theorem other_raw_key_is_literal_input (bound : Nat) (input : RawInput)
    (bounded : input.length ≤ bound) (notLeafLength : input.length ≠ 1407) :
    rawBytes (Sum.inr (otherRawKey bound input bounded notLeafLength)) = input := List.ofFn_get input

theorem full_raw_bytes_injective (bound : Nat) : Function.Injective (@rawBytes bound) := by
  intro left right same
  cases left with
  | inl left =>
      cases right with
      | inl right => exact congrArg Sum.inl (List.ofFn_injective same)
      | inr right =>
          have lengths := congrArg List.length same
          simp only [rawBytes, rawTupleBytes, List.length_ofFn] at lengths
          exact (right.2 lengths.symm).elim
  | inr left =>
      cases right with
      | inl right =>
          have lengths := congrArg List.length same
          simp only [rawBytes, rawTupleBytes, List.length_ofFn] at lengths
          exact (left.2 lengths).elim
      | inr right =>
          exact congrArg Sum.inr (Subtype.ext (raw_tuple_bytes_injective bound same))

theorem source_final_raw_input_length (digestPrefix : Prefix)
    (transcript : PiopCoefficients Goldilocks) :
    (sourceFinalRawInput digestPrefix transcript).length = 25029 := by
  have profile : V8Smz9WholeViewObservation.smz9ProfileDomain.length = 53 := by decide
  have role : SmallWoodTranscript.piopTranscriptDomain.length = 40 := by decide
  simp only [sourceFinalRawInput, counterInput, sourcePrefix, List.length_append,
    encodeLE_length, ← typed_word_payload_is_source_payload, typed_word_payload_length,
    source_final_word_count, profile, role]

/-- This is the source key, embedded without truncation, hashing or aliasing. -/
def sourceFinalKey (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digestPrefix : Prefix) (transcript : PiopCoefficients Goldilocks) : FullRawInput bound :=
  let input := sourceFinalRawInput digestPrefix transcript
  .inr ⟨⟨⟨input.length, by rw [source_final_raw_input_length]; omega⟩, input.get⟩,
    by change input.length ≠ 1407; rw [source_final_raw_input_length]; decide⟩

theorem source_final_key_is_literal_raw_input (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digestPrefix : Prefix) (transcript : PiopCoefficients Goldilocks) :
    rawBytes (sourceFinalKey bound largeEnough digestPrefix transcript) =
      sourceFinalRawInput digestPrefix transcript := List.ofFn_get _

theorem source_final_key_injective (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digestPrefix : Prefix) : Function.Injective (sourceFinalKey bound largeEnough digestPrefix) := by
  intro left right same
  have raw := congrArg rawBytes same
  simp only [source_final_key_is_literal_raw_input] at raw
  exact source_final_raw_input_injective digestPrefix raw

def sourceFinalSampler (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digestPrefix : Prefix) : InputSampler (FullRawInput bound) where
  Coins := PiopCoefficients Goldilocks
  finite := inferInstance
  inhabited := inferInstance
  input := sourceFinalKey bound largeEnough digestPrefix

theorem source_final_sampler_mass (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digestPrefix : Prefix) (input : FullRawInput bound) :
    pmfMap (uniformFintypePMF (sourceFinalSampler bound largeEnough digestPrefix).Coins)
      (sourceFinalSampler bound largeEnough digestPrefix).input input ≤
        ((goldilocksModulus : ℝ≥0∞) ^ 3105)⁻¹ := by
  have mass := uniform_injective_input_max_mass
    (sourceFinalKey bound largeEnough digestPrefix)
    (source_final_key_injective bound largeEnough digestPrefix) input
  simpa only [sourceFinalSampler, full_piop_coordinate_count, Nat.cast_pow] using mass

variable {Work : Type} [Fintype Work]

def sourceFinal (bound : Nat) (largeEnough : 25029 ≤ bound) (digestPrefix : Prefix)
    (next : PiopCoefficients Goldilocks → DigestRegister → Program (FullRawInput bound) Work) :
    Program (FullRawInput bound) Work := .freshInput (sourceFinalSampler bound largeEnough digestPrefix) next

theorem source_final_honest_execution (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digestPrefix : Prefix)
    (next : PiopCoefficients Goldilocks → DigestRegister → Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    run false (sourceFinal bound largeEnough digestPrefix next) oracle state =
      uniformAverage (fun transcript : PiopCoefficients Goldilocks =>
        run false (next transcript (oracle (sourceFinalKey bound largeEnough digestPrefix transcript)))
          oracle state) := by
  simp only [sourceFinal, run, Bool.false_eq_true, if_false, sourceFinalSampler, uniform_average_const]

theorem source_final_randomized_execution (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digestPrefix : Prefix)
    (next : PiopCoefficients Goldilocks → DigestRegister → Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    run true (sourceFinal bound largeEnough digestPrefix next) oracle state =
      uniformAverage (fun transcript : PiopCoefficients Goldilocks =>
        uniformAverage (fun output : DigestRegister =>
          run true (next transcript output)
            (Function.update oracle (sourceFinalKey bound largeEnough digestPrefix transcript) output) state)) := by
  simp only [sourceFinal, run, if_true, sourceFinalSampler, Function.update_self]

theorem source_final_preserves_mass_bound (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digestPrefix : Prefix)
    (next : PiopCoefficients Goldilocks → DigestRegister → Program (FullRawInput bound) Work)
    (remaining : ∀ transcript output,
      InputMassAtMost ((goldilocksModulus : ℝ≥0∞) ^ 3105)⁻¹ (next transcript output)) :
    InputMassAtMost ((goldilocksModulus : ℝ≥0∞) ^ 3105)⁻¹
      (sourceFinal bound largeEnough digestPrefix next) :=
  ⟨source_final_sampler_mass bound largeEnough digestPrefix, remaining⟩

theorem measured_adaptive_final_game_bound (bound : Nat)
    (ghhm : ExternalAdaptiveReprogramming (Input := FullRawInput bound) (Work := Work))
    (program : Program (FullRawInput bound) Work)
    (initial : GameState (Input := FullRawInput bound) (Work := Work))
    (queries attempts : Nat) (normalized : ‖initial‖ = 1)
    (queryBound : queryCount program ≤ queries)
    (attemptBound : programmingCount program ≤ attempts)
    (massBound : InputMassAtMost ((goldilocksModulus : ℝ≥0∞) ^ 3105)⁻¹ program) :
    |acceptance true program initial - acceptance false program initial| ≤
      (attempts : ℝ) * (Real.sqrt ((queries : ℝ) * ((goldilocksModulus : ℝ) ^ 3105)⁻¹) +
        (queries : ℝ) * ((goldilocksModulus : ℝ) ^ 3105)⁻¹ / 2) := by
  apply ghhm program initial queries attempts _ normalized queryBound attemptBound (by positivity)
  simpa only [ENNReal.ofReal_inv_of_pos (by norm_num [goldilocksModulus] :
      (0 : ℝ) < (goldilocksModulus : ℝ) ^ 3105),
    ENNReal.ofReal_pow (Nat.cast_nonneg goldilocksModulus), ENNReal.ofReal_natCast] using massBound

end
end HegemonCrypto.SmallWood.V8Smz9HonestFinalGame
