import HegemonCrypto.SmallWoodV8Smz9SourceBase7
import HegemonCrypto.SmallWoodV8Smz9SourceInactiveMerkleRightRoots
import HegemonCrypto.SmallWoodV8Smz9SourceEarlyCiphertextRoots

/-! The actual 68 input and 24 output inactive raw CSR attempts. Typed
validity supplies inactive witness zeroing; the coefficients are evaluated
from the current CSR DAG rather than assumed. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceInactiveRaw92
open Hegemon.Transaction
open Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceBase7
open HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots
open HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceInactiveMerkleRight
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem typed_inactive_input_source_word_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (offset : Nat)
    (inactive : flagAt statement.inputFlags input.val = 0) : inputWord witness input.val offset = 0 := by
  have zero := typed_inactive_input_zero statement witness valid input inactive
  have noteZero := zero.2.2.2.1
  have positionZero := zero.2.2.2.2.1
  simp only [inputWord,noteZero.1,noteZero.2.1,positionZero,positionBit,
    Nat.zero_div,Nat.zero_mod,ite_self]

theorem typed_inactive_output_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (output : Fin 2)
    (inactive : flagAt statement.outputFlags output.val = 0) :
    ZeroOutputWitness (witness.outputs.getD output.val default) := by
  have facts := valid.2.1.2.2.2.1 output.val output.isLt
  have real : output.val < witness.outputs.length := by rw [valid.2.1.2.1]; exact output.isLt
  simp only [List.getD_eq_getElem _ _ real] at facts ⊢
  have activeZero : witness.outputs[output.val].active = 0 := facts.1.trans inactive
  rw [if_pos activeZero] at facts
  exact facts.2

theorem typed_inactive_output_source_word_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (output : Fin 2) (offset : Fin 12)
    (inactive : flagAt statement.outputFlags output.val = 0) :
    outputWord statement witness output.val offset.val = 0 := by
  have zero := typed_inactive_output_zero statement witness valid output inactive
  have noteZero := zero.2.1
  by_cases value : offset.val = 0
  · simp only [outputWord,if_pos value,noteZero.1]
  by_cases asset : offset.val = 1
  · simp only [outputWord,if_neg value,if_pos asset,noteZero.2.1]
  by_cases ciphertext : offset.val < 8
  · simp only [outputWord,if_neg value,if_neg asset,if_pos ciphertext]
    exact canonical_inactive_ciphertext_zero statement valid.1 output ⟨offset.val - 2,by omega⟩ inactive
  · simp only [outputWord,if_neg value,if_neg asset,if_neg ciphertext]
    exact HegemonCrypto.SmallWood.V8Smz9SourceInactiveMerkleRight.zero_words_getD _
      noteZero.2.2.2.2.2.1 (offset.val - 8)

theorem full_candidate_inactive_input_raw_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (row : Fin 34)
    (inactive : flagAt statement.inputFlags input.val = 0) :
    (fullTypedSourceCandidate statement witness).getD ((34 * input.val + row.val) * 64) 0 = 0 := by
  have readback := full_candidate_raw_word_readback statement witness
    ⟨34 * input.val + row.val,by omega⟩ ⟨0,by decide⟩
  simp only [Nat.add_zero] at readback
  rw [readback,source_input_word statement witness input.val row.val input.isLt row.isLt,
    typed_inactive_input_source_word_zero statement witness valid input row.val inactive]

theorem full_candidate_inactive_output_raw_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (output : Fin 2) (row : Fin 12)
    (inactive : flagAt statement.outputFlags output.val = 0) :
    (fullTypedSourceCandidate statement witness).getD ((68 + 12 * output.val + row.val) * 64) 0 = 0 := by
  have readback := full_candidate_raw_word_readback statement witness
    ⟨68 + 12 * output.val + row.val,by omega⟩ ⟨0,by decide⟩
  simp only [Nat.add_zero] at readback
  rw [readback,source_output_word statement witness output.val row.val output.isLt row.isLt,
    typed_inactive_output_source_word_zero statement witness valid output row inactive]

theorem input_inactive_raw_exact_lookup (input : Fin 2) (row : Fin 34) :
    exactCsrAttempts[15561 + 34 * input.val + row.val]? =
      some (inactiveRawExpectedAttempt input.val row.val) :=
  exact_attempt_lookup _ (exact_inactive_raw_attempts input.val input.isLt row.val row.isLt)

theorem input_inactive_raw_actual_residual_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (row : Fin 34) :
    actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
      (fullTypedSourceCandidate statement witness) (inactiveRawExpectedAttempt input.val row.val) = 0 := by
  simp only [inactiveRawExpectedAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    actual_inactive_right_coefficient _ input,(actual_csr_zero_one _).1,add_zero,sub_zero,
    Poseidon2V8DecoderRefinement.rawIndex,Poseidon2V8DecoderRefinement.rawRowStart,
    Poseidon2V8DecoderRefinement.packingFactor,Nat.zero_add]
  rw [encoded_input_flag statement valid.1 input.isLt]
  have flag := boolean_getD statement.inputFlags valid.1.2.2.1 input.val
  change flagAt statement.inputFlags input.val = 0 ∨ flagAt statement.inputFlags input.val = 1 at flag
  rcases flag with inactive | active
  · rw [full_candidate_inactive_input_raw_zero statement witness valid input row inactive]
    simp only [Nat.cast_zero,mul_zero]
  · rw [active]
    simp only [Nat.cast_one,sub_self,zero_mul]

def outputInactiveRawAttempt (output row : Nat) : CsrExecutableAttempt :=
  attempt (15629 + 12 * output + row) 2 (12 * output + row) 1
    [((68 + 12 * output + row) * 64,126 + output)] 0

def outputInactiveRawChunk (global : Nat) : List CsrExecutableAttempt :=
  if global < 15648 then V8Smz9ProgramCanonicalityCsr30.chunk008
  else V8Smz9ProgramCanonicalityCsr30.chunk009

theorem output_inactive_raw_chunk_member (output : Fin 2) (row : Fin 12) :
    outputInactiveRawAttempt output.val row.val ∈ outputInactiveRawChunk (15629 + 12 * output.val + row.val) := by
  fin_cases output <;> fin_cases row <;> decide

theorem output_inactive_raw_chunk_in_complete (global : Nat) :
    outputInactiveRawChunk global ∈ csrChunks000 := by
  apply base7_csr_chunks030_member
  unfold outputInactiveRawChunk
  split_ifs <;> exact List.mem_append_left _ (by decide)

theorem output_inactive_raw_exact_lookup (output : Fin 2) (row : Fin 12) :
    exactCsrAttempts[15629 + 12 * output.val + row.val]? =
      some (outputInactiveRawAttempt output.val row.val) := by
  have member : outputInactiveRawAttempt output.val row.val ∈ exactCsrAttempts := by
    rw [← csr_chunks_equal_materialized_attempts]
    exact List.mem_flatten.mpr ⟨_,output_inactive_raw_chunk_in_complete _,output_inactive_raw_chunk_member output row⟩
  obtain ⟨position,found⟩ := List.getElem?_of_mem member
  have canonical := checkCsr_sound _ _ _ hgv8rp03_csr_check_passes position _ found
  have same : 15629 + 12 * output.val + row.val = position := canonical.1.1
  rw [same]
  exact found

theorem actual_output_inactive_raw_coefficient (pub : Nat → F) (output : Fin 2) :
    actualCsrCoefficients pub (126 + output.val) = 1 - pub (2 + output.val) := by
  have nodes := exact_inactive_coefficient_nodes (2 + output.val) (by omega)
  have publicEquation := actual_csr_node_field_equation pub nodes.1
  have gateEquation := actual_csr_node_field_equation pub nodes.2.1
  have result : actualCsrCoefficients pub (124 + (2 + output.val)) = 1 - pub (2 + output.val) := by
    simpa only [expressionField,(actual_csr_zero_one pub).2,publicEquation] using gateEquation
  simpa only [← Nat.add_assoc,Nat.reduceAdd] using result

theorem output_inactive_raw_actual_residual_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (output : Fin 2) (row : Fin 12) :
    actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
      (fullTypedSourceCandidate statement witness) (outputInactiveRawAttempt output.val row.val) = 0 := by
  simp only [outputInactiveRawAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    actual_output_inactive_raw_coefficient _ output,(actual_csr_zero_one _).1,add_zero,sub_zero]
  rw [encoded_output_flag statement valid.1 output.isLt]
  have flag := boolean_getD statement.outputFlags valid.1.2.2.2.1 output.val
  change flagAt statement.outputFlags output.val = 0 ∨ flagAt statement.outputFlags output.val = 1 at flag
  rcases flag with inactive | active
  · rw [full_candidate_inactive_output_raw_zero statement witness valid output row inactive]
    simp only [Nat.cast_zero,mul_zero]
  · rw [active]
    simp only [Nat.cast_one,sub_self,zero_mul]

theorem inactive_raw_exact_distinct_count :
    ((List.range 92).map fun i => 15561 + i).length = 92 ∧
      ((List.range 92).map fun i => 15561 + i).Nodup := by decide

theorem full_candidate_actual_inactive_raw92_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 92) :
    (exactCsrAttempts[15561 + index.val]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness)) = some 0 := by
  by_cases input : index.val < 68
  · have split : 15561 + index.val = 15561 + 34 * (index.val / 34) + index.val % 34 := by omega
    rw [split,input_inactive_raw_exact_lookup ⟨index.val / 34,by omega⟩ ⟨index.val % 34,by omega⟩,
      Option.map_some,input_inactive_raw_actual_residual_zero statement witness valid]
  · have split : 15561 + index.val =
        15629 + 12 * ((index.val - 68) / 12) + (index.val - 68) % 12 := by omega
    rw [split,output_inactive_raw_exact_lookup ⟨(index.val - 68) / 12,by omega⟩ ⟨(index.val - 68) % 12,by omega⟩,
      Option.map_some,output_inactive_raw_actual_residual_zero statement witness valid]

end
end HegemonCrypto.SmallWood.V8Smz9SourceInactiveRaw92
