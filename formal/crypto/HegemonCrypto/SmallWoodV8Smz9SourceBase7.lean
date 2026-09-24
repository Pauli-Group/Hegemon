import HegemonCrypto.SmallWoodV8Smz9SourceAuthDigestCsr
import HegemonCrypto.SmallWoodV8Smz9SemanticBalance

/-! Actual transparent-balance and legacy-PRF copy rows, on the original
full source constructor. Only balance rows need typed validity. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceBase7
open Hegemon.Transaction
open Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceTailCsrTable
open HegemonCrypto.SmallWood.V8Smz9SourceTailCsrRoots
open HegemonCrypto.SmallWood.V8Smz9SourceTailCsrReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9ParentRoleCsrReadbacks
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SemanticBalance
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

def balanceZeroAttempt (index : Nat) : CsrExecutableAttempt :=
  attempt (15672 + index) 5 index 0 [(41528,1)] (49 + index)

def legacyCopyAttempt (limb : Nat) : CsrExecutableAttempt :=
  attempt (15805 + limb) 11 limb 0
    [((105 + limb) * 64,1),(Poseidon2V8DecoderRefinement.hashFinalIndex 0 limb,3)] 0

def base7Chunk (global : Nat) : List CsrExecutableAttempt :=
  if global < 15680 then V8Smz9ProgramCanonicalityCsr30.chunk009
  else if global < 15808 then V8Smz9ProgramCanonicalityCsr30.chunk013
  else V8Smz9ProgramCanonicalityCsr30.chunk014

theorem base7_csr_chunks030_member (chunk : List CsrExecutableAttempt)
    (member : chunk ∈ csrChunks030) : chunk ∈ csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (member))))))))))))))))))))))))))))))

theorem base7_chunk_in_complete (global : Nat) : base7Chunk global ∈ csrChunks000 := by
  apply base7_csr_chunks030_member
  unfold base7Chunk
  split_ifs <;> exact List.mem_append_left _ (by decide)

theorem balance_zero_chunk_member (index : Fin 2) :
    balanceZeroAttempt index.val ∈ base7Chunk (15672 + index.val) := by
  fin_cases index <;> decide

theorem legacy_copy_chunk_member (limb : Fin 5) :
    legacyCopyAttempt limb.val ∈ base7Chunk (15805 + limb.val) := by
  fin_cases limb <;> decide

theorem base7_exact_entry (entry : CsrExecutableAttempt)
    (member : entry ∈ base7Chunk entry.globalIndex) :
    exactCsrAttempts[entry.globalIndex]? = some entry := by
  have allMember : entry ∈ exactCsrAttempts := by
    rw [← csr_chunks_equal_materialized_attempts]
    exact List.mem_flatten.mpr ⟨_,base7_chunk_in_complete _,member⟩
  obtain ⟨position,found⟩ := List.getElem?_of_mem allMember
  have canonical := checkCsr_sound _ _ _ hgv8rp03_csr_check_passes position _ found
  rw [canonical.1.1]
  exact found

theorem balance_zero_exact_lookup (index : Fin 2) :
    exactCsrAttempts[15672 + index.val]? = some (balanceZeroAttempt index.val) :=
  base7_exact_entry _ (balance_zero_chunk_member index)

theorem legacy_copy_exact_lookup (limb : Fin 5) :
    exactCsrAttempts[15805 + limb.val]? = some (legacyCopyAttempt limb.val) :=
  base7_exact_entry _ (legacy_copy_chunk_member limb)

theorem actual_balance_target (pub : Nat → F) (index : Fin 2) :
    actualCsrCoefficients pub (49 + index.val) = pub (45 + index.val) := by
  exact actual_csr_node_field_equation pub
    (show exactCsrExpressions[49 + index.val]? = some (.publicWord (45 + index.val)) by
      fin_cases index <;> decide)

theorem encoded_balance_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 2) :
    (encodePublicStatement statement).getD (45 + index.val) 0 = 0 := by
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,signZero,magnitudeZero,_⟩ := valid.1
  fin_cases index
  · exact (encoded_balance_scalar statement valid.1 (index := 1) (by decide)).trans signZero
  · exact (encoded_balance_scalar statement valid.1 (index := 2) (by decide)).trans magnitudeZero

theorem full_candidate_balance_zero_residual (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 2) :
    actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
      (fullTypedSourceCandidate statement witness) (balanceZeroAttempt index.val) = 0 := by
  have padding := full_source_padding_field_zero statement witness ⟨0,by decide⟩
  simp only [Nat.add_zero] at padding
  simp only [balanceZeroAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    (actual_csr_zero_one _).2,one_mul,add_zero,actual_balance_target,
    encoded_balance_zero statement witness valid index,Nat.cast_zero,padding,sub_zero]

theorem full_candidate_legacy_copy_field (statement : V8PublicStatement) (witness : V8Witness)
    (limb : Fin 5) :
    ((fullTypedSourceCandidate statement witness).getD ((105 + limb.val) * 64) 0 : F) =
      (authHashWord (typedSourceFinals statement witness) 0 limb.val : F) := by
  exact parent_auth_family_field statement witness .legacy limb.val limb.isLt

theorem full_candidate_legacy_final_field (statement : V8PublicStatement) (witness : V8Witness)
    (limb : Fin 5) :
    ((fullTypedSourceCandidate statement witness).getD
      (Poseidon2V8DecoderRefinement.hashFinalIndex 0 limb.val) 0 : F) =
      (authHashWord (typedSourceFinals statement witness) 0 limb.val : F) := by
  rw [full_candidate_final_schedule_readback statement witness ⟨0,by decide⟩ ⟨limb.val,by omega⟩,
    auth_hash_word_readback _ ⟨0,by decide⟩ ⟨limb.val,by omega⟩,
    typed_source_finals_are_actual_schedule statement witness ⟨0,by decide⟩ ⟨limb.val,by omega⟩]

theorem full_candidate_legacy_copy_residual (statement : V8PublicStatement) (witness : V8Witness)
    (limb : Fin 5) :
    actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
      (fullTypedSourceCandidate statement witness) (legacyCopyAttempt limb.val) = 0 := by
  let pub : Nat → F := fun slot => ((encodePublicStatement statement).getD slot 0 : F)
  change actualCsrResidual pub _ _ = 0
  simp only [legacyCopyAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    (actual_csr_zero_one pub).1,(actual_csr_zero_one pub).2,
    actual_tail_negative_one_coefficient pub,one_mul,add_zero,sub_zero]
  rw [full_candidate_legacy_copy_field,full_candidate_legacy_final_field]
  ring

def base7Index (index : Nat) : Nat :=
  if index < 2 then 15672 + index else 15805 + (index - 2)

theorem base7_exact_distinct_count :
    ((List.range 7).map base7Index).length = 7 ∧ ((List.range 7).map base7Index).Nodup := by decide

theorem full_candidate_actual_base7_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 7) :
    (exactCsrAttempts[base7Index index.val]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness)) = some 0 := by
  by_cases balance : index.val < 2
  · rw [base7Index,if_pos balance,balance_zero_exact_lookup ⟨index.val,balance⟩,
      Option.map_some,full_candidate_balance_zero_residual statement witness valid ⟨index.val,balance⟩]
  · rw [base7Index,if_neg balance,legacy_copy_exact_lookup ⟨index.val - 2,by omega⟩,
      Option.map_some,full_candidate_legacy_copy_residual statement witness ⟨index.val - 2,by omega⟩]

end
end HegemonCrypto.SmallWood.V8Smz9SourceBase7
