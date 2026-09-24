import HegemonCrypto.SmallWoodV8Smz9CurrentRepeatedPrivacy
import HegemonCrypto.SmallWoodV8Smz9RawCounterCompiler

/-! The full honest-side final PIOP input after the joint Q/M change of
coordinates. All3105 coefficients are retained in their alternating source
order. The eight SHA-512 prefix words remain unrestricted u64 words. Exact
role/length/u64/counter framing is reused from the source raw-query compiler.
The fresh sampler is input-first; this module does not condition its coins on
the desired final digest or on the later opening points. -/

namespace HegemonCrypto.SmallWood.V8Smz9HonestWholeViewFinalInput

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution V8Smz9RuntimeFieldLayout
open V8Smz9EagerPrivacy V8Smz9RawCounterCompiler
open scoped BigOperators ENNReal Classical

noncomputable section
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

abbrev RawWord := Fin (2 ^ 64)
abbrev Prefix := Fin 8 → RawWord

def alternatingCoefficientEquiv : (Fin 3105 → Goldilocks) ≃ PiopCoefficients Goldilocks :=
  (alternatingMasksEquiv Goldilocks).trans (sourceMaskCoefficientEquiv Goldilocks)

def fieldWord (value : Goldilocks) : RawWord :=
  ⟨fromGoldilocks value, lt_trans (fromGoldilocks_lt value) (by norm_num [goldilocksModulus])⟩

theorem field_word_injective : Function.Injective fieldWord := by
  intro left right same
  have values := congrArg (fun word : RawWord => word.val) same
  exact ZMod.val_injective _ values

def sourceFinalWords (digestPrefix : Prefix) (transcript : PiopCoefficients Goldilocks) : List RawWord :=
  List.ofFn digestPrefix ++ List.ofFn fun index : Fin 3105 => fieldWord (alternatingCoefficientEquiv.symm transcript index)

theorem source_final_word_count (digestPrefix : Prefix) (transcript : PiopCoefficients Goldilocks) :
    (sourceFinalWords digestPrefix transcript).length = 3113 := by
  simp only [sourceFinalWords, List.length_append, List.length_ofFn]

theorem source_final_words_injective (digestPrefix : Prefix) :
    Function.Injective (sourceFinalWords digestPrefix) := by
  intro left right same
  have tails := List.append_cancel_left same
  have coordinates := List.ofFn_injective tails
  apply alternatingCoefficientEquiv.symm.injective
  funext index
  exact field_word_injective (congrFun coordinates index)

def sourceFinalRawInput (digestPrefix : Prefix) (transcript : PiopCoefficients Goldilocks) : RawInput :=
  counterInput
    (sourcePrefix SmallWoodTranscript.piopTranscriptDomain ((sourceFinalWords digestPrefix transcript).map Fin.val))
    ⟨0, by norm_num⟩

theorem source_final_raw_input_is_exact_key (digestPrefix : Prefix) (transcript : PiopCoefficients Goldilocks) :
    sourceFinalRawInput digestPrefix transcript =
      (V8Smz9WholeViewObservation.RawSha512OracleKey.mk
        (some V8Smz9WholeViewObservation.smz9ProfileDomain)
        SmallWoodTranscript.piopTranscriptDomain ((sourceFinalWords digestPrefix transcript).map Fin.val) 0).preimage :=
  source_counter_input_is_exact_raw_key _ _ ⟨0, by norm_num⟩

theorem source_final_raw_input_injective (digestPrefix : Prefix) :
    Function.Injective (sourceFinalRawInput digestPrefix) := by
  intro left right same
  have framed := typed_source_counter_frame_injective
    SmallWoodTranscript.piopTranscriptDomain SmallWoodTranscript.piopTranscriptDomain
    (sourceFinalWords digestPrefix left) (sourceFinalWords digestPrefix right)
    ⟨0, by norm_num⟩ ⟨0, by norm_num⟩
    (by decide) (by decide)
    (by rw [source_final_word_count]; norm_num)
    (by rw [source_final_word_count]; norm_num) same
  exact source_final_words_injective digestPrefix framed.2.1

theorem full_piop_coordinate_count :
    Fintype.card (PiopCoefficients Goldilocks) = goldilocksModulus ^ 3105 := by
  rw [← Fintype.card_congr alternatingCoefficientEquiv]
  simp only [Fintype.card_fun, Fintype.card_fin, goldilocks_card]

/-- A generic finite pushforward fact proved from the actual sampled law. -/
theorem uniform_injective_input_max_mass {Coins Input : Type*} [Fintype Coins] [Nonempty Coins]
    (encode : Coins → Input) (injective : Function.Injective encode) (input : Input) :
    pmfMap (uniformFintypePMF Coins) encode input ≤ (Fintype.card Coins : ℝ≥0∞)⁻¹ := by
  rw [pmfMap_apply, tsum_fintype]
  by_cases present : ∃ coin, input = encode coin
  · obtain ⟨coin, rfl⟩ := present
    rw [Finset.sum_eq_single coin]
    · simp only [ite_true, uniformFintypePMF_apply, le_refl]
    · intro other _ different
      rw [if_neg]
      exact fun equal => different (injective equal).symm
    · intro absent
      exact (absent (Finset.mem_univ _)).elim
  · have absent : ∀ coin, input ≠ encode coin := by simpa only [not_exists] using present
    simp only [if_neg (absent _), Finset.sum_const_zero, zero_le]

/-- Exact honest-side input mass after the full Q/M transport. This is a
fresh product sampler at a fixed earlier prefix, not a postselected law. -/
theorem source_final_raw_input_max_mass (digestPrefix : Prefix) (input : RawInput) :
    pmfMap (uniformFintypePMF (PiopCoefficients Goldilocks))
      (sourceFinalRawInput digestPrefix) input ≤ ((goldilocksModulus : ℝ≥0∞) ^ 3105)⁻¹ := by
  have bound := uniform_injective_input_max_mass (sourceFinalRawInput digestPrefix)
    (source_final_raw_input_injective digestPrefix) input
  simpa only [full_piop_coordinate_count, Nat.cast_pow] using bound

end
end HegemonCrypto.SmallWood.V8Smz9HonestWholeViewFinalInput
