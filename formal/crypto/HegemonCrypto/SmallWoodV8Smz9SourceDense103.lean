import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate
import HegemonCrypto.SmallWoodV8Smz9SourceDenseCsr
import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityGenerated
import Mathlib.Tactic.LinearCombination

/-! Bounded source-only construction for the two dense padding CSR families.
    This is deliberately limited to actual residuals and lookup evidence:
    it does not assert desired-zero, accepted, or evaluator-premise facts. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceDense103

open Hegemon.Transaction
open Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceDenseMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceDensePrefix
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

def denseFamily6Attempt (index : Nat) : CsrExecutableAttempt :=
  attempt (15674 + index) 6 index 0 [(16018 + index, 1)] 0

def denseFamily7Attempt (index : Nat) : CsrExecutableAttempt :=
  attempt (15720 + index) 7 index 0 [(16071 + index, 1)] 0

def densePaddingChunk (global : Nat) : List CsrExecutableAttempt :=
  if global < 15680 then V8Smz9ProgramCanonicalityCsr30.chunk009
  else if global < 15712 then V8Smz9ProgramCanonicalityCsr30.chunk010
  else if global < 15744 then V8Smz9ProgramCanonicalityCsr30.chunk011
  else if global < 15776 then V8Smz9ProgramCanonicalityCsr30.chunk012
  else V8Smz9ProgramCanonicalityCsr30.chunk013

theorem dense_csr_chunks030_member (chunk : List CsrExecutableAttempt)
    (member : chunk ∈ csrChunks030) : chunk ∈ csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (member))))))))))))))))))))))))))))))

theorem dense_padding_chunk_in_complete (global : Nat) :
    densePaddingChunk global ∈ csrChunks000 := by
  apply dense_csr_chunks030_member
  unfold densePaddingChunk
  split_ifs <;> exact List.mem_append_left _ (by decide)

theorem dense_family6_chunk_member (index : Fin 46) :
    denseFamily6Attempt index.val ∈ densePaddingChunk (15674 + index.val) := by
  fin_cases index <;> decide

theorem dense_family7_chunk_member (index : Fin 57) :
    denseFamily7Attempt index.val ∈ densePaddingChunk (15720 + index.val) := by
  fin_cases index <;> decide

theorem dense_padding_exact_entry (entry : CsrExecutableAttempt)
    (member : entry ∈ densePaddingChunk entry.globalIndex) :
    exactCsrAttempts[entry.globalIndex]? = some entry := by
  have allMember : entry ∈ exactCsrAttempts := by
    rw [← csr_chunks_equal_materialized_attempts]
    exact List.mem_flatten.mpr ⟨_, dense_padding_chunk_in_complete _, member⟩
  obtain ⟨position, found⟩ := List.getElem?_of_mem allMember
  have canonical := checkCsr_sound _ _ _ hgv8rp03_csr_check_passes position _ found
  rw [canonical.1.1]
  exact found

theorem dense_family6_attempt_lookup (index : Fin 46) :
    exactCsrAttempts[15674 + index.val]? = some (denseFamily6Attempt index.val) :=
  dense_padding_exact_entry _ (dense_family6_chunk_member index)

theorem dense_family7_attempt_lookup (index : Fin 57) :
    exactCsrAttempts[15720 + index.val]? = some (denseFamily7Attempt index.val) :=
  dense_padding_exact_entry _ (dense_family7_chunk_member index)

theorem full_candidate_dense_padding_zero (statement : V8PublicStatement) (witness : V8Witness)
    (slot : Fin 320) (padding : (210 ≤ slot.val ∧ slot.val < 256) ∨ 263 ≤ slot.val) :
    (fullTypedSourceCandidate statement witness).getD (15808 + slot.val) 0 = 0 := by
  change (constructedAssignment statement witness (typedLiveInitialStates statement witness)
    (typedSourceTail statement witness)).getD (15808 + slot.val) 0 = 0
  rw [constructed_as_dense_composition]
  unfold composedAssignment
  have beforeLength := before_dense_length statement witness
    (authBlock statement witness (typedLiveInitialStates statement witness))
    (auth_block_length statement witness (typedLiveInitialStates statement witness))
  have address : 15808 + slot.val =
      (beforeDense statement witness
        (authBlock statement witness (typedLiveInitialStates statement witness))).length + slot.val := by
    rw [beforeLength]
  rw [address,source_dense_embedded_getD]
  exact source_dense_padding_zero _ _ padding

theorem dense_family6_actual_residual_zero (statement : V8PublicStatement)
    (witness : V8Witness) (index : Fin 46) :
    actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
      (fullTypedSourceCandidate statement witness) (denseFamily6Attempt index.val) = 0 := by
  have padding := full_candidate_dense_padding_zero statement witness
    ⟨210 + index.val,by omega⟩ (by
      change (210 ≤ 210 + index.val ∧ 210 + index.val < 256) ∨ 263 ≤ 210 + index.val
      omega)
  have address : 15808 + (210 + index.val) = 16018 + index.val := by omega
  rw [address] at padding
  simp only [denseFamily6Attempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    (actual_csr_zero_one _).1,(actual_csr_zero_one _).2,
    one_mul,padding,Nat.cast_zero,add_zero,sub_zero]

theorem dense_family7_actual_residual_zero (statement : V8PublicStatement)
    (witness : V8Witness) (index : Fin 57) :
    actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
      (fullTypedSourceCandidate statement witness) (denseFamily7Attempt index.val) = 0 := by
  have padding := full_candidate_dense_padding_zero statement witness
    ⟨263 + index.val,by omega⟩ (by
      change (210 ≤ 263 + index.val ∧ 263 + index.val < 256) ∨ 263 ≤ 263 + index.val
      omega)
  have address : 15808 + (263 + index.val) = 16071 + index.val := by omega
  rw [address] at padding
  simp only [denseFamily7Attempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    (actual_csr_zero_one _).1,(actual_csr_zero_one _).2,
    one_mul,padding,Nat.cast_zero,add_zero,sub_zero]

def densePadding103Indices : List Nat := (List.range 103).map (15674 + ·)

theorem dense_padding103_count : densePadding103Indices.length = 103 := by decide

theorem dense_padding103_nodup : densePadding103Indices.Nodup := by decide

theorem full_candidate_dense_padding103_indexed (statement : V8PublicStatement)
    (witness : V8Witness) (index : Fin 103) :
    (exactCsrAttempts[15674 + index.val]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness)) = some 0 := by
  by_cases low : index.val < 46
  · rw [dense_family6_attempt_lookup ⟨index.val, low⟩, Option.map_some]
    exact congrArg some (dense_family6_actual_residual_zero statement witness ⟨index.val, low⟩)
  · have bound : index.val - 46 < 57 := by omega
    have address : 15674 + index.val = 15720 + (index.val - 46) := by omega
    rw [address, dense_family7_attempt_lookup ⟨index.val - 46, bound⟩, Option.map_some]
    exact congrArg some (dense_family7_actual_residual_zero statement witness ⟨index.val - 46, bound⟩)

theorem full_candidate_dense_padding103_results (statement : V8PublicStatement)
    (witness : V8Witness) :
    densePadding103Indices.length = 103 ∧ densePadding103Indices.Nodup ∧
    (densePadding103Indices.map fun global => (exactCsrAttempts[global]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness))) = List.replicate 103 (some 0) := by
  refine ⟨dense_padding103_count, dense_padding103_nodup, ?_⟩
  have equal : (densePadding103Indices.map fun global => (exactCsrAttempts[global]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness))) =
      densePadding103Indices.map (fun _ => some (0 : F)) := by
    apply List.map_congr_left
    intro global member
    change global ∈ (List.range 103).map (15674 + ·) at member
    obtain ⟨index, bound, equal⟩ := List.mem_map.mp member
    rw [← equal]
    exact full_candidate_dense_padding103_indexed statement witness
      ⟨index, List.mem_range.mp bound⟩
  simpa only [List.map_const', dense_padding103_count] using equal

end
end HegemonCrypto.SmallWood.V8Smz9SourceDense103
