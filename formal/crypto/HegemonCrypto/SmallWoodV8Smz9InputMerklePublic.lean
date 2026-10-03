import HegemonCrypto.SmallWoodV8Smz9InputMerkleFrames

namespace HegemonCrypto.SmallWood.V8Smz9InputMerklePublic

open Hegemon.Transaction hiding Digest
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashFinalIndex inputMerkleCall)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
open HegemonCrypto.SmallWood.V8Smz9Compress14Endpoint
open HegemonCrypto.SmallWood.V8Smz9InputMerkleFrames

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

def inputRootAttempt (input limb : Nat) : CsrExecutableAttempt :=
  attempt (18286 + 7 * input + limb) 18 (7 * input + limb) 1
    [(hashFinalIndex (inputMerkleCall input 31) limb, 4 + input)]
    (199 + 75 * input + limb)

private theorem root_chunk_member :
    V8Smz9ProgramCanonicalityCsr35.chunk011 ∈
      V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  apply List.mem_append_right
  exact List.mem_append_left _ (by simp [V8Smz9ProgramCanonicalityCsr35.chunkList])

theorem exact_input_root_attempt (input : Fin 2) (limb : Fin 7) :
    inputRootAttempt input.val limb.val ∈ exactCsrAttempts := by
  have checked : ∀ input : Fin 2, ∀ limb : Fin 7,
      inputRootAttempt input.val limb.val ∈ V8Smz9ProgramCanonicalityCsr35.chunk011 := by decide
  rw [← V8Smz9ProgramCanonicalityGenerated.csr_chunks_equal_materialized_attempts]
  exact List.mem_flatten.mpr ⟨_, root_chunk_member, checked input limb⟩

theorem exact_input_root_nodes : ∀ input : Fin 2, ∀ limb : Fin 7,
    exactCsrExpressions[4 + input.val]? = some (.publicWord input.val) ∧
    exactCsrExpressions[51 + limb.val]? = some (.publicWord (47 + limb.val)) ∧
    exactCsrExpressions[199 + 75 * input.val + limb.val]? =
      some (.mul (4 + input.val) (51 + limb.val)) := by decide

theorem accepted_active_input_root_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (input : Fin 2) (limb : Fin 7) (active : publicWords.getD input.val 0 = 1) :
    packedWord packed (hashFinalIndex (inputMerkleCall input.val 31) limb.val) =
      publicWords.getD (47 + limb.val) 0 := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have nodes := exact_input_root_nodes input limb
  have flagValue : (values.getD (4 + input.val) 0 : F) = 1 := by
    simpa only [expressionField, active, Nat.cast_one] using equations _ _ nodes.1
  have publicValue : (values.getD (51 + limb.val) 0 : F) =
      (publicWords.getD (47 + limb.val) 0 : F) := by
    simpa only [expressionField] using equations _ _ nodes.2.1
  have targetValue : (values.getD (199 + 75 * input.val + limb.val) 0 : F) =
      (publicWords.getD (47 + limb.val) 0 : F) := by
    simpa only [expressionField, flagValue, publicValue, one_mul] using equations _ _ nodes.2.2
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_input_root_attempt input limb))
  have publicBound := (canonical_public_coordinate accepted.1
    (index := 47 + limb.val) (by have := limb.isLt; change _ < 120; omega)).2
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) publicBound
  simpa only [inputRootAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, flagValue, targetValue, one_mul, add_zero, packedWord] using equation

theorem encoded_merkle_root_word (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    {limb : Nat} (bound : limb < 7) :
    (encodePublicStatement statement).getD (47 + limb) 0 = statement.merkleRoot.getD limb 0 := by
  obtain ⟨inputLength, outputLength, nullifierLength, commitmentLength,
    ciphertextLength, rootLength, _⟩ := admitted_public_lengths statement canonical
  let publicPrefix := statement.inputFlags ++ statement.outputFlags ++ statement.nullifiers.flatten ++
    statement.commitments.flatten ++ statement.ciphertextCommitments.flatten ++
    [statement.fee, statement.valueBalanceSign, statement.valueBalanceMagnitude]
  have prefixLength : publicPrefix.length = 47 := by
    simp [publicPrefix, inputLength, outputLength, nullifierLength, commitmentLength, ciphertextLength]
  have encoded : encodePublicStatement statement = publicPrefix ++
      (statement.merkleRoot ++ statement.balanceAssets ++ encodeCompatibility statement.compatibility ++
        [statement.version, statement.cryptoSuite] ++ encodeStablecoinPublic statement.stablecoin) := by
    simp only [encodePublicStatement, publicPrefix, List.append_assoc]
  rw [encoded, List.getD_append_right _ _ _ _ (by omega), prefixLength]
  have offset : 47 + limb - 47 = limb := by omega
  rw [offset]
  simpa only [List.append_assoc] using
    List.getD_append statement.merkleRoot
      (statement.balanceAssets ++ encodeCompatibility statement.compatibility ++
        [statement.version, statement.cryptoSuite] ++ encodeStablecoinPublic statement.stablecoin)
      0 limb (by omega)

/-- Exact active-input Merkle semantics from the actual accepted packed source
and public admission; no Merkle/hash equality is supplied as a premise. -/
theorem admitted_packed_project_typed_merkle_roots {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    ∀ slot, slot < inputCount → flagAt statement.inputFlags slot = 1 →
      exactV8SemanticPrimitives.merkleRoot
        (exactV8SemanticPrimitives.noteCommitment
          ((projectTypedWitness statement packed).inputs.getD slot default).note)
        ((projectTypedWitness statement packed).inputs.getD slot default).position
        ((projectTypedWitness statement packed).inputs.getD slot default).siblings =
          statement.merkleRoot := by
  intro slot slotBound active
  have bound : slot < 2 := slotBound
  have rawActive : publicWords.getD slot 0 = 1 := by
    rw [← domain.1, encoded_input_flag statement domain.2.1 bound]
    exact active
  rw [project_typed_input_at statement packed default bound]
  change exactV8MerkleRoot (exactV8NoteCommitment (projectInput statement packed slot).note)
    (projectInput statement packed slot).position (projectInput statement packed slot).siblings = _
  rw [accepted_merkle_root_eq_final_digest domain.2.2 statement ⟨slot, bound⟩]
  have rootLength := (admitted_public_lengths statement domain.2.1).2.2.2.2.2.1
  apply List.ext_getElem
  · simp [callDigest, packedFinalState, digestWords, rootLength]
  · intro limb leftBound rightBound
    have limbBound : limb < 7 := by simpa only [rootLength] using rightBound
    have word := accepted_active_input_root_word domain.2.2 ⟨slot, bound⟩ ⟨limb, limbBound⟩ rawActive
    rw [← domain.1, encoded_merkle_root_word statement domain.2.1 limbBound] at word
    have rootWord : statement.merkleRoot.getD limb 0 = statement.merkleRoot[limb] := by
      simp [List.getD_eq_getElem?_getD, rightBound]
    rw [rootWord] at word
    simpa only [callDigest, packedFinalState, List.getElem_take, List.getElem_map,
      List.getElem_range] using word


end HegemonCrypto.SmallWood.V8Smz9InputMerklePublic
