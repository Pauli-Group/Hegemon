import HegemonCrypto.SmallWoodV8Smz9SemanticEndpointPrf
import HegemonCrypto.SmallWoodV8Smz9SemanticAuthorization

namespace HegemonCrypto.SmallWood.V8Smz9SemanticEndpointPrfLegacy

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
  (CsrExecutableAttempt evalFieldExpression fieldSub fieldNormalize)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (rawIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointPrf

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

def prfLegacyAttempt (limb : Nat) : CsrExecutableAttempt :=
  attempt (15805 + limb) 11 limb 0 [(rawIndex (105 + limb), 1), (hashFinalIndex 0 limb, 3)] 0

theorem prf_legacy_source (limb : Fin 5) : prfLegacyAttempt limb.val ∈ exactCsrAttempts := by
  have checked : ∀ limb : Fin 5, prfLegacyAttempt limb.val ∈
      V8Smz9ProgramCanonicalityCsr30.chunk013 ++ V8Smz9ProgramCanonicalityCsr30.chunk014 := by decide
  rw [← V8Smz9ProgramCanonicalityGenerated.csr_chunks_equal_materialized_attempts]
  rcases List.mem_append.mp (checked limb) with first | second
  · apply List.mem_flatten_of_mem _ first
    unfold
      V8Smz9ProgramCanonicalityGenerated.csrChunks000
      V8Smz9ProgramCanonicalityGenerated.csrChunks001
      V8Smz9ProgramCanonicalityGenerated.csrChunks002
      V8Smz9ProgramCanonicalityGenerated.csrChunks003
      V8Smz9ProgramCanonicalityGenerated.csrChunks004
      V8Smz9ProgramCanonicalityGenerated.csrChunks005
      V8Smz9ProgramCanonicalityGenerated.csrChunks006
      V8Smz9ProgramCanonicalityGenerated.csrChunks007
      V8Smz9ProgramCanonicalityGenerated.csrChunks008
      V8Smz9ProgramCanonicalityGenerated.csrChunks009
      V8Smz9ProgramCanonicalityGenerated.csrChunks010
      V8Smz9ProgramCanonicalityGenerated.csrChunks011
      V8Smz9ProgramCanonicalityGenerated.csrChunks012
      V8Smz9ProgramCanonicalityGenerated.csrChunks013
      V8Smz9ProgramCanonicalityGenerated.csrChunks014
      V8Smz9ProgramCanonicalityGenerated.csrChunks015
      V8Smz9ProgramCanonicalityGenerated.csrChunks016
      V8Smz9ProgramCanonicalityGenerated.csrChunks017
      V8Smz9ProgramCanonicalityGenerated.csrChunks018
      V8Smz9ProgramCanonicalityGenerated.csrChunks019
      V8Smz9ProgramCanonicalityGenerated.csrChunks020
      V8Smz9ProgramCanonicalityGenerated.csrChunks021
      V8Smz9ProgramCanonicalityGenerated.csrChunks022
      V8Smz9ProgramCanonicalityGenerated.csrChunks023
      V8Smz9ProgramCanonicalityGenerated.csrChunks024
      V8Smz9ProgramCanonicalityGenerated.csrChunks025
      V8Smz9ProgramCanonicalityGenerated.csrChunks026
      V8Smz9ProgramCanonicalityGenerated.csrChunks027
      V8Smz9ProgramCanonicalityGenerated.csrChunks028
      V8Smz9ProgramCanonicalityGenerated.csrChunks029
      V8Smz9ProgramCanonicalityGenerated.csrChunks030
    simp only [List.mem_append]
    aesop (add simp [V8Smz9ProgramCanonicalityCsr30.chunkList])
  · exact List.mem_flatten_of_mem
      (note_frame_chunk_mem_exact (by simp [noteFrameChunks])) second

theorem accepted_legacy_word_eq_hash_final {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (limb : Fin 5) :
    authorizationRawWord packed (105 + limb.val) = packedWord packed (hashFinalIndex 0 limb.val) := by
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have constants := csr_trace_zero_one_values equations
  have minusFound : values[3]? = some (fieldSub 0 1) := by
    simpa [evalFieldExpression, fieldSub, fieldNormalize,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
      equations 3 (.constant 18446744069414584320) (by decide)
  have minusValue : (values.getD 3 0 : F) = -1 := by
    simp only [List.getD_eq_getElem?_getD, minusFound, Option.getD_some]
    rw [field_sub_cast 0 1 (by decide)]
    simp
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simp [List.getD_eq_getElem?_getD, constants.2]
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp [List.getD_eq_getElem?_getD, constants.1]
  have equation := accepted_csr_attempt_field_equality (attempts _ (prf_legacy_source limb))
  simp only [prfLegacyAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, oneValue, minusValue, zeroValue,
    one_mul, neg_one_mul, add_zero, ← sub_eq_add_neg] at equation
  have equal := canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _) (sub_eq_zero.mp equation)
  simpa only [authorizationRawWord, packedWord, rawIndex,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.zero_add] using equal

theorem accepted_legacy_word_eq_exact_prf {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (limb : Fin 5) :
    authorizationRawWord packed (105 + limb.val) =
      (exactV8TransactionPrf (prfWords packed)).getD limb.val 0 := by
  rw [← accepted_prf_digest_eq_exact accepted]
  have taken : ((packedFinalState packed 0).take digestWords).getD limb.val 0 =
      (packedFinalState packed 0).getD limb.val 0 := by
    simp only [List.getD_eq_getElem?_getD,
      List.getElem?_take_of_lt (by change limb.val < 7; omega : limb.val < digestWords)]
  rw [taken, packed_final_getD packed 0 (by omega)]
  exact accepted_legacy_word_eq_hash_final accepted limb

theorem accepted_legacy_key_eq_exact_prf {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    (List.range 4).map (fun limb => authorizationRawWord packed (106 + limb)) =
      ((exactV8TransactionPrf (prfWords packed)).drop 1).take 4 := by
  rw [← accepted_prf_digest_eq_exact accepted]
  apply List.ext_getElem
  · simp [packedFinalState, digestWords]
  · intro limb leftBound rightBound
    have bound : limb < 4 := by simpa using leftBound
    simp only [List.getElem_map, List.getElem_range, List.getElem_take, List.getElem_drop,
      packedFinalState]
    have result := accepted_legacy_word_eq_hash_final accepted ⟨1 + limb, by omega⟩
    have row : 105 + (1 + limb) = 106 + limb := by omega
    rw [row] at result
    exact result

theorem selected_project_transaction_spend_key (statement : V8PublicStatement) (packed : List Nat)
    {input : Nat} (bound : input < 2) (active : flagAt statement.inputFlags input = 1) :
    selectedTransactionSpendKey statement (projectTypedWitness statement packed) = prfWords packed := by
  by_cases first : flagAt statement.inputFlags 0 = 1
  · rw [selected_transaction_spend_key_first_active _ _ first,
      project_typed_input_at statement packed _ (by decide)]
    simp only [projectInput, first, Nat.one_ne_zero, ↓reduceIte, prfWords]
  · have inputOne : input = 1 := by
      by_contra different
      have inputZero : input = 0 := by omega
      exact first (inputZero ▸ active)
    subst input
    simp only [selectedTransactionSpendKey, first, if_false, active, if_true]
    rw [project_typed_input_at statement packed _ (by decide)]
    simp only [projectInput, active, Nat.one_ne_zero, ↓reduceIte, prfWords]


end HegemonCrypto.SmallWood.V8Smz9SemanticEndpointPrfLegacy
