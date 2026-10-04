import HegemonCrypto.SmallWoodV8Smz9FullRateSourceComposition
import HegemonCrypto.SmallWoodV8Smz9SemanticAuthorization

namespace HegemonCrypto.SmallWood.V8Smz9ActionIntentSourceWords

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9FullRateSourceFrames
open HegemonCrypto.SmallWood.V8Smz9FullRateSourceComposition
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField canonical_getD)

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

def ActionIntentExcluded (word : Nat) : Prop :=
  (4 ≤ word ∧ word < 18) ∨ (47 ≤ word ∧ word < 54) ∨
    (87 ≤ word ∧ word < 94) ∨ (113 ≤ word ∧ word < 120)

instance (word : Nat) : Decidable (ActionIntentExcluded word) := by
  unfold ActionIntentExcluded
  infer_instance

def actionIntentWordTarget (word : Nat) : Nat := if ActionIntentExcluded word then 0 else 4 + word

def actionIntentProjectedWord (publicWords : List Nat) (word : Nat) : Nat :=
  if ActionIntentExcluded word then 0 else publicWords.getD word 0

def actionIntentWordAttempt (word : Nat) : CsrExecutableAttempt :=
  let block := word / 8
  let call := 79 + block
  attempt (18468 + 16 * block + word % 8) 24 (16 * block + word % 8) 0
    ([(hashInitialIndex call (word % 8), 1)] ++
      if block = 0 then [] else [(hashFinalIndex (call - 1) (word % 8), 158)])
    (actionIntentWordTarget word)

theorem action_intent_word_source (word : Fin 120) :
    actionIntentWordAttempt word.val ∈ exactCsrAttempts := by
  have checked : ∀ word : Fin 120, actionIntentWordAttempt word.val ∈
      V8Smz9ProgramCanonicalityCsr36.chunkList.flatten := by decide
  obtain ⟨chunk, member, entry⟩ := List.mem_flatten.mp (checked word)
  rw [← V8Smz9ProgramCanonicalityGenerated.csr_chunks_equal_materialized_attempts]
  exact List.mem_flatten.mpr ⟨chunk, full_rate_csr_chunk_mem_exact member, entry⟩

theorem action_intent_public_node (word : Fin 120) :
    exactCsrExpressions[4 + word.val]? = some (.publicWord word.val) := by
  have checked : ∀ word : Fin 120,
      exactCsrExpressions[4 + word.val]? = some (.publicWord word.val) := by decide
  exact checked word

/-- All120 source-absorbed intent words equal the exact public projection;
excluded ranges are proved zero, not copied from untrusted private state. -/
theorem accepted_action_intent_source_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (word : Fin 120) :
    spongeSourceWord packed 79 word.val = actionIntentProjectedWord publicWords word.val := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField, Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField, Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have negValue : (values.getD 158 0 : F) = -1 := by
    simpa only [expressionField, zeroValue, oneValue, zero_sub] using equations 158 (.sub 0 1) (by decide)
  have targetValue : (values.getD (actionIntentWordTarget word.val) 0 : F) =
      (actionIntentProjectedWord publicWords word.val : F) := by
    by_cases excluded : ActionIntentExcluded word.val
    · simpa only [actionIntentWordTarget, actionIntentProjectedWord, if_pos excluded, Nat.cast_zero] using zeroValue
    · simpa only [actionIntentWordTarget, actionIntentProjectedWord, if_neg excluded, expressionField] using
        equations _ _ (action_intent_public_node word)
  have targetBound : actionIntentProjectedWord publicWords word.val < fieldModulus := by
    unfold actionIntentProjectedWord
    split
    · decide
    · exact canonical_getD publicWords accepted.1.2 word.val
  have equation := accepted_csr_attempt_field_equality (attempts _ (action_intent_word_source word))
  apply canonical_nat_cast_injective (sponge_source_word_canonical accepted.2.1 _ _) targetBound
  by_cases first : word.val / 8 = 0
  · simp only [actionIntentWordAttempt, attempt, first, if_true, List.append_nil,
      csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      oneValue, one_mul, add_zero, targetValue] at equation
    simpa only [spongeSourceWord, first, if_true, Nat.add_zero, packedWord] using equation
  · simp only [actionIntentWordAttempt, attempt, first, if_false, List.cons_append,
      List.nil_append, csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      oneValue, one_mul, negValue, neg_one_mul, add_zero, targetValue] at equation
    simp only [spongeSourceWord, first, if_false]
    rw [field_sub_cast _ _ (by
      have previous := packed_word_canonical accepted.2.1
        (hashFinalIndex (79 + word.val / 8 - 1) (word.val % 8))
      change _ < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus at previous
      omega)]
    simpa only [packedWord, sub_eq_add_neg] using equation

theorem admitted_action_intent_source_words {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    fullRateSourceWords packed 0 = exactV8ActionIntentProjection statement := by
  change (List.range 120).map (spongeSourceWord packed 79) =
    (List.range 120).map (fun word =>
      if ActionIntentExcluded word then 0 else (encodePublicStatement statement).getD word 0)
  rw [domain.1]
  apply List.map_congr_left
  intro word member
  exact accepted_action_intent_source_word domain.2.2 ⟨word, List.mem_range.mp member⟩

theorem admitted_action_intent_digest_eq_exact {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    (packedFinalState packed 93).take digestWords = exactV8ActionIntent statement := by
  have digest := accepted_full_rate_sponge_digest domain.2.2 ⟨0, by decide⟩
  simp only [fullRateSourceCall, fullRateSourceBlocks, fullRateSourceDomain,
    if_true, Nat.reduceAdd, Nat.reduceSub] at digest
  rw [admitted_action_intent_source_words domain] at digest
  exact digest


end HegemonCrypto.SmallWood.V8Smz9ActionIntentSourceWords
