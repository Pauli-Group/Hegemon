import HegemonCrypto.SmallWoodV8Smz9SemanticBalance

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization

open Hegemon.Transaction.Poseidon2V8SemanticSpecification

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

/-- Seven canonical digest words for each of the source's 125 hash calls.
Their equality to the typed hash schedule is a later, separate binding. -/
abbrev AuthHashFinals := Fin 125 → Fin 7 → Nat

def HashFinalsCanonical (hashes : AuthHashFinals) : Prop :=
  ∀ call limb, hashes call limb < fieldModulus

def authHashWord (hashes : AuthHashFinals) (call limb : Nat) : Nat :=
  if callBound : call < 125 then
    if limbBound : limb < 7 then hashes ⟨call, callBound⟩ ⟨limb, limbBound⟩ else 0
  else 0

theorem auth_hash_word_canonical (hashes : AuthHashFinals)
    (canonical : HashFinalsCanonical hashes) (call limb : Nat) :
    authHashWord hashes call limb < fieldModulus := by
  unfold authHashWord
  split_ifs
  · exact canonical _ _
  · decide
  · decide

theorem auth_hash_word_readback (hashes : AuthHashFinals) (call : Fin 125) (limb : Fin 7) :
    authHashWord hashes call.val limb.val = hashes call limb := by
  simp only [authHashWord, dif_pos call.isLt, dif_pos limb.isLt]

theorem auth_exact_words_getD {count : Nat} {words : List Nat}
    (canonical : ExactWords count words) (index : Nat) :
    words.getD index 0 < fieldModulus := by
  cases found : words[index]? with
  | none => simp only [List.getD_eq_getElem?_getD, found, Option.getD_none]; decide
  | some value =>
      simp only [List.getD_eq_getElem?_getD, found, Option.getD_some]
      exact canonical.2 value (List.mem_of_getElem? found)

def AccumulatorSourceCanonical (opening : V8AccumulatorOpening) : Prop :=
  (∀ limb, wordAt opening.intentDigest limb < fieldModulus) ∧
  opening.threshold < fieldModulus ∧ opening.signerCount < fieldModulus ∧
  opening.approvalCount < fieldModulus ∧
  ∀ slot, slot < 6 → wordAt opening.approvedSlots slot < fieldModulus

theorem zero_accumulator_source_canonical (opening : V8AccumulatorOpening)
    (zero : ZeroAccumulator opening) : AccumulatorSourceCanonical opening := by
  obtain ⟨_, _, intent, _, threshold, signers, count, _, approved⟩ := zero
  refine ⟨fun limb => auth_exact_words_getD intent limb, ?_, ?_, ?_, ?_⟩
  · rw [threshold]; decide
  · rw [signers]; decide
  · rw [count]; decide
  · intro slot _
    unfold wordAt
    cases found : opening.approvedSlots[slot]? with
    | none => simp only [List.getD_eq_getElem?_getD, found, Option.getD_none]; decide
    | some value =>
        have isZero := approved value (List.mem_of_getElem? found)
        simp only [List.getD_eq_getElem?_getD, found, Option.getD_some, isZero]
        decide

theorem canonical_accumulator_source_canonical (opening : V8AccumulatorOpening)
    (canonical : CanonicalAccumulator opening) : AccumulatorSourceCanonical opening := by
  obtain ⟨_, _, intent, _, _, threshold, signers, count, _, approved, _, _⟩ := canonical
  have signersBound : opening.signerCount ≤ 6 := by
    simpa only [signerCountMaximum] using signers
  have modulus : 6 < fieldModulus := by decide
  refine ⟨fun limb => auth_exact_words_getD intent limb, by omega, by omega, by omega, ?_⟩
  intro slot bound
  have boolean := approved slot (by simpa only [signerCountMaximum] using bound)
  rcases boolean with zero | one
  · rw [zero]; decide
  · rw [one]; decide

def AuthTypedSourceCanonical (auth : V8AuthorizationWitness) : Prop :=
  AccumulatorSourceCanonical auth.current ∧ AccumulatorSourceCanonical auth.next ∧
  ∀ slot, slot < 6 → ∀ limb,
    wordAt (auth.policySignerTags.getD slot []) limb < fieldModulus

theorem zero_signer_tags_source_canonical (tags : List (List Nat))
    (zero : ZeroSignerTags tags) (slot : Nat) (bound : slot < 6) (limb : Nat) :
    wordAt (tags.getD slot []) limb < fieldModulus := by
  obtain ⟨length, words⟩ := zero
  have indexBound : slot < tags.length := by
    rw [length]
    simpa only [signerCountMaximum] using bound
  have found : tags[slot]? = some (tags.getD slot []) := by simp [List.getD, indexBound]
  exact auth_exact_words_getD (words _ (List.mem_of_getElem? found)).1 limb

theorem canonical_signer_tags_source_canonical (auth : V8AuthorizationWitness)
    (canonical : CanonicalSignerTags auth) (slot : Nat) (bound : slot < 6) (limb : Nat) :
    wordAt (auth.policySignerTags.getD slot []) limb < fieldModulus := by
  exact auth_exact_words_getD (canonical.2.1 slot
    (by simpa only [signerCountMaximum] using bound)) limb

theorem valid_auth_typed_source_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    AuthTypedSourceCanonical witness.authorization := by
  have auth := valid.2.2.1.2.2
  cases mode : witness.authorization.mode with
  | singleKey =>
      simp only [V8AuthorizationValid, mode] at auth
      exact ⟨zero_accumulator_source_canonical _ auth.1,
        zero_accumulator_source_canonical _ auth.2.1,
        fun slot bound limb => zero_signer_tags_source_canonical _ auth.2.2.1 slot bound limb⟩
  | approvalStep =>
      simp only [V8AuthorizationValid, mode] at auth
      exact ⟨canonical_accumulator_source_canonical _ auth.2.2.1,
        canonical_accumulator_source_canonical _ auth.2.2.2.1,
        fun slot bound limb => canonical_signer_tags_source_canonical _ auth.2.2.2.2.1 slot bound limb⟩
  | finalThresholdSpend =>
      simp only [V8AuthorizationValid, mode] at auth
      exact ⟨canonical_accumulator_source_canonical _ auth.2.1,
        zero_accumulator_source_canonical _ auth.2.2.1,
        fun slot bound limb => canonical_signer_tags_source_canonical _ auth.2.2.2.1 slot bound limb⟩


end HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
