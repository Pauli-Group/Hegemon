import HegemonCrypto.SmallWoodV8Smz9PrfLegacyBinding

namespace HegemonCrypto.SmallWood.V8Smz9AuthorizationDigestCopies

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

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

def authorizationDigestCall (digest : Nat) : Nat :=
  if digest = 0 then 100 else if digest = 1 then 103 else 105

def authorizationDigestAttemptIndex (digest : Nat) : Nat :=
  if digest = 0 then 19019 else if digest = 1 then 19074 else 19113

def authorizationDigestCopyAttempt (digest limb : Nat) : CsrExecutableAttempt :=
  attempt (authorizationDigestAttemptIndex digest + limb) (30 + 2 * digest) limb 0
    [(rawIndex (110 + 7 * digest + limb), 1), (hashFinalIndex (authorizationDigestCall digest) limb, 3)] 0

theorem authorization_csr_chunk_mem_exact {chunk : List CsrExecutableAttempt}
    (member : chunk ∈ V8Smz9ProgramCanonicalityCsr37.chunkList) :
    chunk ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
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
    V8Smz9ProgramCanonicalityGenerated.csrChunks031
    V8Smz9ProgramCanonicalityGenerated.csrChunks032
    V8Smz9ProgramCanonicalityGenerated.csrChunks033
    V8Smz9ProgramCanonicalityGenerated.csrChunks034
    V8Smz9ProgramCanonicalityGenerated.csrChunks035
    V8Smz9ProgramCanonicalityGenerated.csrChunks036
    V8Smz9ProgramCanonicalityGenerated.csrChunks037
  simp only [List.mem_append]
  aesop

theorem authorization_digest_copy_source (digest : Fin 3) (limb : Fin 7) :
    authorizationDigestCopyAttempt digest.val limb.val ∈ exactCsrAttempts := by
  have checked : ∀ digest : Fin 3, ∀ limb : Fin 7,
      authorizationDigestCopyAttempt digest.val limb.val ∈
        V8Smz9ProgramCanonicalityCsr37.chunkList.flatten := by decide
  obtain ⟨chunk, chunkMember, entryMember⟩ := List.mem_flatten.mp (checked digest limb)
  rw [← V8Smz9ProgramCanonicalityGenerated.csr_chunks_equal_materialized_attempts]
  exact List.mem_flatten.mpr ⟨chunk, authorization_csr_chunk_mem_exact chunkMember, entryMember⟩

theorem accepted_authorization_digest_copy {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (digest : Fin 3) (limb : Fin 7) :
    authorizationRawWord packed (110 + 7 * digest.val + limb.val) =
      packedWord packed (hashFinalIndex (authorizationDigestCall digest.val) limb.val) := by
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
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (authorization_digest_copy_source digest limb))
  simp only [authorizationDigestCopyAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, oneValue, minusValue, zeroValue,
    one_mul, neg_one_mul, add_zero, ← sub_eq_add_neg] at equation
  have equal := canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _) (sub_eq_zero.mp equation)
  simpa only [authorizationRawWord, packedWord, rawIndex,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.zero_add] using equal

theorem accepted_authorization_digest_copy_list {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (digest : Fin 3) :
    (List.range 7).map (fun limb => authorizationRawWord packed (110 + 7 * digest.val + limb)) =
      (packedFinalState packed (authorizationDigestCall digest.val)).take digestWords := by
  apply List.ext_getElem
  · simp [packedFinalState, digestWords]
  · intro limb leftBound rightBound
    have bound : limb < 7 := by simpa using leftBound
    simp only [packedFinalState, List.getElem_map, List.getElem_range, List.getElem_take]
    exact accepted_authorization_digest_copy accepted digest ⟨limb, bound⟩


end HegemonCrypto.SmallWood.V8Smz9AuthorizationDigestCopies
