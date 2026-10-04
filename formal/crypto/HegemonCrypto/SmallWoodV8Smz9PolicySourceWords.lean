import HegemonCrypto.SmallWoodV8Smz9FullRateSourceComposition
import HegemonCrypto.SmallWoodV8Smz9SemanticAuthorization

namespace HegemonCrypto.SmallWood.V8Smz9PolicySourceWords

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (rawIndex hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9FullRateSourceFrames
open HegemonCrypto.SmallWood.V8Smz9FullRateSourceComposition

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

def policyWordRow (word : Nat) : Nat :=
  if word = 0 then 152 else if word = 1 then 153 else 194 + word

def policyWordAttempt (word : Nat) : CsrExecutableAttempt :=
  let block := word / 8
  let call := 94 + block
  attempt (18715 + 16 * block + word % 8) 26 (16 * block + word % 8) 0
    ([(hashInitialIndex call (word % 8), 1)] ++
      (if block = 0 then [] else [(hashFinalIndex (call - 1) (word % 8), 158)]) ++
      [(rawIndex (policyWordRow word), 158)]) 0

theorem policy_word_source (word : Nat) (bound : word < 32) :
    policyWordAttempt word ∈ exactCsrAttempts := by
  have checked : ∀ word : Fin 32, policyWordAttempt word.val ∈
      V8Smz9ProgramCanonicalityCsr36.chunkList.flatten := by decide
  obtain ⟨chunk, member, entry⟩ := List.mem_flatten.mp (checked ⟨word, bound⟩)
  rw [← V8Smz9ProgramCanonicalityGenerated.csr_chunks_equal_materialized_attempts]
  exact List.mem_flatten.mpr ⟨chunk, full_rate_csr_chunk_mem_exact member, entry⟩

theorem accepted_policy_source_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {word : Nat} (bound : word < 32) :
    spongeSourceWord packed 94 word = authorizationRawWord packed (policyWordRow word) := by
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have constants := csr_trace_zero_one_values equations
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp only [List.getD_eq_getElem?_getD, constants.1, Option.getD_some, Nat.cast_zero]
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simp only [List.getD_eq_getElem?_getD, constants.2, Option.getD_some, Nat.cast_one]
  have negativeOne : (values.getD 158 0 : F) = -1 := by
    simpa using (dense_negative_coefficient_values equations).1 0 (by decide)
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (policy_word_source word bound))
  apply canonical_nat_cast_injective (sponge_source_word_canonical accepted.2.1 _ _)
    (packed_word_canonical accepted.2.1 _)
  by_cases firstBlock : word / 8 = 0
  · simp only [policyWordAttempt, attempt, firstBlock, if_true,
      List.append_nil, List.cons_append, List.nil_append, csrFieldSum,
      List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      oneValue, negativeOne, zeroValue, one_mul, neg_one_mul, add_zero] at equation
    have equality := sub_eq_zero.mp (by simpa only [sub_eq_add_neg] using equation)
    simpa only [spongeSourceWord, firstBlock, if_true, Nat.add_zero,
      authorizationRawWord, rawIndex,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
      Nat.zero_add, packedWord] using equality
  · simp only [policyWordAttempt, attempt, firstBlock, if_false,
      List.cons_append, List.nil_append, csrFieldSum,
      List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      oneValue, negativeOne, zeroValue, one_mul, neg_one_mul, add_zero] at equation
    simp only [spongeSourceWord, firstBlock, if_false]
    rw [field_sub_cast _ _ (by
      have previous := packed_word_canonical accepted.2.1 (hashFinalIndex (94 + word / 8 - 1) (word % 8))
      change _ < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus at previous
      omega)]
    have equality : (packed.getD (hashInitialIndex (94 + word / 8) (word % 8)) 0 : F) -
        (packed.getD (hashFinalIndex (94 + word / 8 - 1) (word % 8)) 0 : F) =
        (packed.getD (rawIndex (policyWordRow word)) 0 : F) := by
      exact sub_eq_zero.mp (by simpa only [sub_eq_add_neg, add_assoc] using equation)
    simpa only [packedWord, authorizationRawWord, rawIndex,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.zero_add] using equality


theorem policy_word_layout (word : Nat → Nat) :
    (List.range 32).map (fun index => word (policyWordRow index)) =
      [word 152, word 153] ++
        ((List.range 6).map (fun slot => (List.range 5).map
          (fun limb => word (196 + slot * 5 + limb)))).flatten := by
  rfl

theorem accepted_policy_source_words {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    fullRateSourceWords packed 1 =
      [(projectAuthorization packed).current.threshold, (projectAuthorization packed).current.signerCount] ++
        (projectAuthorization packed).policySignerTags.flatten := by
  have source : fullRateSourceWords packed 1 =
      (List.range 32).map (fun word => authorizationRawWord packed (policyWordRow word)) := by
    apply List.map_congr_left
    intro word member
    exact accepted_policy_source_word accepted (List.mem_range.mp member)
  rw [source, policy_word_layout]
  have threshold := accepted_current_opening_source_word accepted (word := 14) (by decide)
  have signer := accepted_current_opening_source_word accepted (word := 15) (by decide)
  change _ = [spongeSourceWord packed 98 14, spongeSourceWord packed 98 15] ++ _
  rw [threshold, signer]
  rfl

theorem accepted_policy_digest_eq_exact {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    (packedFinalState packed 97).take digestWords =
      exactV8PolicyRoot (projectAuthorization packed).policySignerTags
        (projectAuthorization packed).current.threshold (projectAuthorization packed).current.signerCount := by
  have digest := accepted_full_rate_sponge_digest accepted ⟨1, by decide⟩
  simp only [fullRateSourceCall, fullRateSourceBlocks, fullRateSourceDomain,
    Nat.one_ne_zero, if_false, Nat.reduceAdd, Nat.reduceSub] at digest
  rw [accepted_policy_source_words accepted] at digest
  exact digest


end HegemonCrypto.SmallWood.V8Smz9PolicySourceWords
