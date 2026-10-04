import HegemonCrypto.SmallWoodV8Smz9SemanticCanonicalWitness

namespace HegemonCrypto.SmallWood.V8Smz9NoteOutputPublic

open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashFinalIndex outputNoteCall)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

def outputCommitmentAttempt (output limb : Nat) : CsrExecutableAttempt :=
  attempt (18454 + 7 * output + limb) 23 (7 * output + limb) 1
    [(hashFinalIndex (outputNoteCall output + 2) limb, 6 + output)]
    (289 + 8 * output + limb)

private theorem csr36_entry_mem_exact {chunk : List CsrExecutableAttempt}
    {entry : CsrExecutableAttempt}
    (chunkMem : chunk ∈ V8Smz9ProgramCanonicalityCsr36.chunkList)
    (entryMem : entry ∈ chunk) : entry ∈ exactCsrAttempts := by
  rw [← V8Smz9ProgramCanonicalityGenerated.csr_chunks_equal_materialized_attempts]
  apply List.mem_flatten_of_mem _ entryMem
  unfold V8Smz9ProgramCanonicalityGenerated.csrChunks000
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
  simp only [List.mem_append]
  aesop

theorem exact_output_commitment_attempts (output : Fin 2) (limb : Fin 7) :
    outputCommitmentAttempt output.val limb.val ∈ exactCsrAttempts := by
  have checked : ∀ output : Fin 2, ∀ limb : Fin 7,
      outputCommitmentAttempt output.val limb.val ∈ V8Smz9ProgramCanonicalityCsr36.chunk000 ∨
      outputCommitmentAttempt output.val limb.val ∈ V8Smz9ProgramCanonicalityCsr36.chunk001 := by
    decide
  rcases checked output limb with first | second
  · exact csr36_entry_mem_exact (by simp [V8Smz9ProgramCanonicalityCsr36.chunkList]) first
  · exact csr36_entry_mem_exact (by simp [V8Smz9ProgramCanonicalityCsr36.chunkList]) second

theorem exact_output_commitment_nodes : ∀ output : Fin 2, ∀ limb : Fin 7,
    exactCsrExpressions[6 + output.val]? = some (.publicWord (2 + output.val)) ∧
    exactCsrExpressions[22 + 7 * output.val + limb.val]? =
      some (.publicWord (18 + 7 * output.val + limb.val)) ∧
    exactCsrExpressions[289 + 8 * output.val + limb.val]? =
      some (.mul (6 + output.val) (22 + 7 * output.val + limb.val)) := by
  decide

/-- Every active output commitment limb is the final limb of its actual note
sponge, derived from the pinned family-23 equation and canonical field words. -/
theorem accepted_active_output_commitment_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (output : Fin 2) (limb : Fin 7)
    (active : publicWords.getD (2 + output.val) 0 = 1) :
    packedWord packed (hashFinalIndex (outputNoteCall output.val + 2) limb.val) =
      publicWords.getD (18 + 7 * output.val + limb.val) 0 := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have nodes := exact_output_commitment_nodes output limb
  have flagValue : (values.getD (6 + output.val) 0 : F) = 1 := by
    simpa only [expressionField, active, Nat.cast_one] using equations _ _ nodes.1
  have publicValue : (values.getD (22 + 7 * output.val + limb.val) 0 : F) =
      (publicWords.getD (18 + 7 * output.val + limb.val) 0 : F) := by
    simpa only [expressionField] using equations _ _ nodes.2.1
  have targetValue : (values.getD (289 + 8 * output.val + limb.val) 0 : F) =
      (publicWords.getD (18 + 7 * output.val + limb.val) 0 : F) := by
    simpa only [expressionField, flagValue, publicValue, one_mul] using equations _ _ nodes.2.2
  have fieldEquation := accepted_csr_attempt_field_equality
    (attempts _ (exact_output_commitment_attempts output limb))
  have publicBound := (canonical_public_coordinate accepted.1
    (index := 18 + 7 * output.val + limb.val) (by
      have := output.isLt; have := limb.isLt
      change _ < 120
      omega)).2
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) publicBound
  simp only [outputCommitmentAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil] at fieldEquation
  rw [flagValue, targetValue, one_mul, add_zero] at fieldEquation
  simpa only [packedWord] using fieldEquation

theorem encoded_public_commitment_word (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    (output : Fin 2) (limb : Fin 7) :
    (encodePublicStatement statement).getD (18 + 7 * output.val + limb.val) 0 =
      (digestAt statement.commitments output.val).getD limb.val 0 := by
  obtain ⟨inputLength, outputLength, nullifierFlatLength, commitmentFlatLength,
    ciphertextFlatLength, rootLength, assetLength⟩ := admitted_public_lengths statement canonical
  let publicPrefix := statement.inputFlags ++ statement.outputFlags ++ statement.nullifiers.flatten
  have prefixLength : publicPrefix.length = 18 := by
    simp [publicPrefix, inputLength, outputLength, nullifierFlatLength]
  have encoded : encodePublicStatement statement = publicPrefix ++
      (statement.commitments.flatten ++
        (statement.ciphertextCommitments.flatten ++
          [statement.fee, statement.valueBalanceSign, statement.valueBalanceMagnitude] ++
          statement.merkleRoot ++ statement.balanceAssets ++
          encodeCompatibility statement.compatibility ++
          [statement.version, statement.cryptoSuite] ++ encodeStablecoinPublic statement.stablecoin)) := by
    simp only [encodePublicStatement, publicPrefix, List.append_assoc]
  rw [encoded, List.getD_append_right _ _ _ _ (by omega), prefixLength]
  have offset : 18 + 7 * output.val + limb.val - 18 = 7 * output.val + limb.val := by omega
  rw [offset, List.getD_append _ _ _ _ (by
    have := output.isLt; have := limb.isLt; omega)]
  obtain ⟨_, _, _, _, _, _, commitmentCount, commitmentWords, _⟩ := canonical
  obtain ⟨first, second, chunks⟩ := List.length_eq_two.mp commitmentCount
  have firstLength : first.length = 7 :=
    (commitmentWords first (by simp [chunks])).1
  fin_cases output
  · simpa [chunks, digestAt] using
      List.getD_append first second 0 limb.val (by have := limb.isLt; omega)
  · simpa [chunks, digestAt, firstLength] using
      List.getD_append_right first second 0 (7 + limb.val) (by omega)

theorem admitted_active_output_commitment_word {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (output : Fin 2) (limb : Fin 7)
    (active : flagAt statement.outputFlags output.val = 1) :
    packedWord packed (hashFinalIndex (outputNoteCall output.val + 2) limb.val) =
      (digestAt statement.commitments output.val).getD limb.val 0 := by
  have rawActive : publicWords.getD (2 + output.val) 0 = 1 := by
    rw [← domain.1, encoded_output_flag statement domain.2.1 output.isLt, active]
  rw [accepted_active_output_commitment_word domain.2.2 output limb rawActive,
    ← domain.1, encoded_public_commitment_word statement domain.2.1 output limb]

theorem admitted_public_commitment_digest {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (output : Fin 2) :
    (List.range 7).map (fun limb => publicWords.getD (18 + 7 * output.val + limb) 0) =
      digestAt statement.commitments output.val := by
  obtain ⟨_, _, _, _, _, _, commitmentCount, commitmentWords, _⟩ := domain.2.1
  have outputBound : output.val < statement.commitments.length := by
    rw [commitmentCount]
    exact output.isLt
  have found : statement.commitments[output.val]? =
      some (digestAt statement.commitments output.val) := by
    simp [digestAt, List.getD, outputBound]
  have digestLength : (digestAt statement.commitments output.val).length = 7 :=
    (commitmentWords _ (List.mem_of_getElem? found)).1
  apply List.ext_getElem (by simp [digestLength])
  intro limb leftBound rightBound
  have limbBound : limb < 7 := by simpa using leftBound
  simp only [List.getElem_map, List.getElem_range]
  rw [← domain.1, encoded_public_commitment_word statement domain.2.1 output ⟨limb, limbBound⟩]
  exact List.getD_eq_getElem _ _ rightBound

end HegemonCrypto.SmallWood.V8Smz9NoteOutputPublic
