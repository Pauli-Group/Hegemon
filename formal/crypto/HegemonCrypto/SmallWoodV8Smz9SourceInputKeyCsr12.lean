import HegemonCrypto.SmallWoodV8Smz9SourceInactiveMerkleRightRoots
import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityGenerated

/-! Eight inactive-key and four shared-key CSR equations on the actual
full source constructor, from the existing typed witness relation. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceInputKeyCsr12
open Hegemon.Transaction
open Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceInactiveMerkleRight
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

def inactiveKeyAttempt (input limb : Nat) : CsrExecutableAttempt :=
  attempt (15777 + 2 * limb + input) 8 (2 * limb + input) 1 [(41520 + input * 4 + limb,124 + input)] 0

def sharedKeyAttempt (limb : Nat) : CsrExecutableAttempt :=
  attempt (15785 + limb) 9 limb 1 [(41520 + limb,193),(41524 + limb,194)] 0

theorem key_csr_chunks030_member (chunk : List CsrExecutableAttempt)
    (member : chunk ∈ csrChunks030) : chunk ∈ csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (member))))))))))))))))))))))))))))))

theorem key_chunk_in_complete : V8Smz9ProgramCanonicalityCsr30.chunk013 ∈ csrChunks000 :=
  key_csr_chunks030_member _ (List.mem_append_left _ (by decide))

theorem inactive_key_chunk_member (input : Fin 2) (limb : Fin 4) :
    inactiveKeyAttempt input.val limb.val ∈ V8Smz9ProgramCanonicalityCsr30.chunk013 := by
  fin_cases input <;> fin_cases limb <;> decide

theorem shared_key_chunk_member (limb : Fin 4) :
    sharedKeyAttempt limb.val ∈ V8Smz9ProgramCanonicalityCsr30.chunk013 := by
  fin_cases limb <;> decide

theorem key_exact_entry (entry : CsrExecutableAttempt)
    (member : entry ∈ V8Smz9ProgramCanonicalityCsr30.chunk013) :
    exactCsrAttempts[entry.globalIndex]? = some entry := by
  have allMember : entry ∈ exactCsrAttempts := by
    rw [← csr_chunks_equal_materialized_attempts]
    exact List.mem_flatten.mpr ⟨_,key_chunk_in_complete,member⟩
  obtain ⟨position,found⟩ := List.getElem?_of_mem allMember
  have canonical := checkCsr_sound _ _ _ hgv8rp03_csr_check_passes position _ found
  rw [canonical.1.1]
  exact found

theorem inactive_key_exact_lookup (input : Fin 2) (limb : Fin 4) :
    exactCsrAttempts[15777 + 2 * limb.val + input.val]? = some (inactiveKeyAttempt input.val limb.val) :=
  key_exact_entry _ (inactive_key_chunk_member input limb)

theorem shared_key_exact_lookup (limb : Fin 4) :
    exactCsrAttempts[15785 + limb.val]? = some (sharedKeyAttempt limb.val) :=
  key_exact_entry _ (shared_key_chunk_member limb)

theorem full_candidate_inactive_key_word_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (limb : Fin 4)
    (inactive : flagAt statement.inputFlags input.val = 0) :
    (fullTypedSourceCandidate statement witness).getD (41520 + input.val * 4 + limb.val) 0 = 0 := by
  rw [full_candidate_spend_keys_readback]
  exact zero_words_getD _ (typed_inactive_input_zero statement witness valid input inactive).2.2.1 limb.val

theorem full_candidate_inactive_key_residual_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (limb : Fin 4) :
    actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
      (fullTypedSourceCandidate statement witness) (inactiveKeyAttempt input.val limb.val) = 0 := by
  simp only [inactiveKeyAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    actual_inactive_right_coefficient _ input,(actual_csr_zero_one _).1,add_zero,sub_zero]
  rw [encoded_input_flag statement valid.1 input.isLt]
  have flag := boolean_getD statement.inputFlags valid.1.2.2.1 input.val
  change flagAt statement.inputFlags input.val = 0 ∨ flagAt statement.inputFlags input.val = 1 at flag
  rcases flag with inactive | active
  · rw [full_candidate_inactive_key_word_zero statement witness valid input limb inactive]
    simp only [Nat.cast_zero,mul_zero]
  · rw [active]
    simp only [Nat.cast_one,sub_self,zero_mul]

theorem actual_shared_key_coefficients (pub : Nat → F) :
    actualCsrCoefficients pub 193 = pub 0 * pub 1 ∧
      actualCsrCoefficients pub 194 = -(pub 0 * pub 1) := by
  have p0 := actual_csr_node_field_equation pub (show exactCsrExpressions[4]? = some (.publicWord 0) by decide)
  have p1 := actual_csr_node_field_equation pub (show exactCsrExpressions[5]? = some (.publicWord 1) by decide)
  have both := actual_csr_node_field_equation pub (show exactCsrExpressions[193]? = some (.mul 4 5) by decide)
  have negative := actual_csr_node_field_equation pub (show exactCsrExpressions[194]? = some (.sub 0 193) by decide)
  have product : actualCsrCoefficients pub 193 = pub 0 * pub 1 := by
    simpa only [expressionField,p0,p1] using both
  exact ⟨product,by simpa only [expressionField,(actual_csr_zero_one pub).1,product,zero_sub] using negative⟩

theorem typed_active_spend_keys_equal (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (first : flagAt statement.inputFlags 0 = 1) (second : flagAt statement.inputFlags 1 = 1) :
    (witness.inputs.getD 0 default).spendKey = (witness.inputs.getD 1 default).spendKey :=
  valid.2.1.2.2.2.2.1 first second

theorem full_candidate_shared_key_residual_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (limb : Fin 4) :
    actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
      (fullTypedSourceCandidate statement witness) (sharedKeyAttempt limb.val) = 0 := by
  let pub : Nat → F := fun slot => ((encodePublicStatement statement).getD slot 0 : F)
  change actualCsrResidual pub _ _ = 0
  simp only [sharedKeyAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    (actual_shared_key_coefficients pub).1,(actual_shared_key_coefficients pub).2,
    (actual_csr_zero_one pub).1,add_zero,sub_zero]
  have key0 := full_candidate_spend_keys_readback statement witness ⟨0,by decide⟩ limb
  have key1 := full_candidate_spend_keys_readback statement witness ⟨1,by decide⟩ limb
  norm_num only at key0 key1
  rw [key0,key1]
  dsimp only [pub]
  rw [encoded_input_flag statement valid.1 (by decide : 0 < 2),
    encoded_input_flag statement valid.1 (by decide : 1 < 2)]
  have first := boolean_getD statement.inputFlags valid.1.2.2.1 0
  have second := boolean_getD statement.inputFlags valid.1.2.2.1 1
  change flagAt statement.inputFlags 0 = 0 ∨ flagAt statement.inputFlags 0 = 1 at first
  change flagAt statement.inputFlags 1 = 0 ∨ flagAt statement.inputFlags 1 = 1 at second
  rcases first with zero | one
  · rw [zero]
    simp only [Nat.cast_zero,zero_mul,neg_zero,zero_add]
  · rcases second with zero | other
    · rw [zero]
      simp only [Nat.cast_zero,mul_zero,neg_zero,zero_mul,zero_add]
    · rw [typed_active_spend_keys_equal statement witness valid one other]
      ring

theorem input_key_csr_exact_distinct_count :
    ((List.range 12).map fun i => 15777 + i).length = 12 ∧
      ((List.range 12).map fun i => 15777 + i).Nodup := by decide

theorem full_candidate_actual_all12_input_key_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 12) :
    (exactCsrAttempts[15777 + index.val]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness)) = some 0 := by
  by_cases inactive : index.val < 8
  · have split : 15777 + index.val = 15777 + 2 * (index.val / 2) + index.val % 2 := by omega
    rw [split,inactive_key_exact_lookup ⟨index.val % 2,by omega⟩ ⟨index.val / 2,by omega⟩,
      Option.map_some,full_candidate_inactive_key_residual_zero statement witness valid]
  · have split : 15777 + index.val = 15785 + (index.val - 8) := by omega
    rw [split,shared_key_exact_lookup ⟨index.val - 8,by omega⟩,
      Option.map_some,full_candidate_shared_key_residual_zero statement witness valid]

end
end HegemonCrypto.SmallWood.V8Smz9SourceInputKeyCsr12
