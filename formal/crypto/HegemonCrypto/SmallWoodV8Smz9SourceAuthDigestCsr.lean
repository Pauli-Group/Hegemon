import HegemonCrypto.SmallWoodV8Smz9ParentRoleCsrReadbacks
import HegemonCrypto.SmallWoodV8Smz9SourceTailCsrRoots

/-! Actual statement/current/next/value-lock digest copies. Both operands are
read from the same full constructor; validity is not an extra equality premise. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthDigestCsr
open Hegemon.Transaction
open Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceTailCsrTable
open HegemonCrypto.SmallWood.V8Smz9SourceTailCsrRoots
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9ParentRoleCsrReadbacks
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

inductive DigestCopyFamily where
  | statement | current | next | valueLock
  deriving DecidableEq

def DigestCopyFamily.start : DigestCopyFamily → Nat
  | .statement => 18708 | .current => 19019 | .next => 19074 | .valueLock => 19113

def DigestCopyFamily.familyId : DigestCopyFamily → Nat
  | .statement => 25 | .current => 30 | .next => 32 | .valueLock => 34

def DigestCopyFamily.sourceFamily : DigestCopyFamily → AuthFamily
  | .statement => .statementDigest | .current => .current | .next => .next | .valueLock => .valueLock

def DigestCopyFamily.call : DigestCopyFamily → Nat
  | .statement => 93 | .current => 100 | .next => 103 | .valueLock => 105

def digestCopyAttempt (family : DigestCopyFamily) (limb : Nat) : CsrExecutableAttempt :=
  attempt (family.start + limb) family.familyId limb 0
    [((92 + family.sourceFamily.base + limb) * 64,1),
     (Poseidon2V8DecoderRefinement.hashFinalIndex family.call limb,3)] 0

def digestCopyChunk : DigestCopyFamily → List CsrExecutableAttempt
  | .statement => HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr36.chunk008
  | .current => HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr37.chunk002
  | .next => HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr37.chunk004
  | .valueLock => HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr37.chunk005

theorem digest_copy_chunk_member (family : DigestCopyFamily) (limb : Fin 7) :
    digestCopyAttempt family limb.val ∈ digestCopyChunk family := by
  cases family <;> fin_cases limb <;> decide

theorem digest_csr_chunks036_member (chunk : List CsrExecutableAttempt) (member : chunk ∈ csrChunks036) :
    chunk ∈ csrChunks000 := by
  exact List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ (member))))))))))))))))))))))))))))))))))))

theorem digest_copy_chunk_in_complete_table (family : DigestCopyFamily) :
    digestCopyChunk family ∈ csrChunks000 := by
  cases family with
  | statement =>
      have localMember : HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr36.chunk008 ∈
          HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr36.chunkList := by decide
      have member : digestCopyChunk .statement ∈ csrChunks036 := List.mem_append_left _ localMember
      exact digest_csr_chunks036_member _ member
  | current =>
      apply csr_chunks037_member
      exact List.mem_append_left _ (by decide : HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr37.chunk002 ∈
        HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr37.chunkList)
  | next =>
      apply csr_chunks037_member
      exact List.mem_append_left _ (by decide : HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr37.chunk004 ∈
        HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr37.chunkList)
  | valueLock =>
      apply csr_chunks037_member
      exact List.mem_append_left _ (by decide : HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr37.chunk005 ∈
        HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr37.chunkList)

theorem exact_digest_copy_attempt_lookup (family : DigestCopyFamily) (limb : Fin 7) :
    exactCsrAttempts[family.start + limb.val]? = some (digestCopyAttempt family limb.val) := by
  have member : digestCopyAttempt family limb.val ∈ exactCsrAttempts := by
    rw [← csr_chunks_equal_materialized_attempts]
    exact List.mem_flatten.mpr ⟨_,digest_copy_chunk_in_complete_table family,digest_copy_chunk_member family limb⟩
  obtain ⟨position,found⟩ := List.getElem?_of_mem member
  have canonical := checkCsr_sound _ _ _ hgv8rp03_csr_check_passes position _ found
  have same : family.start + limb.val = position := canonical.1.1
  rw [same]
  exact found

theorem full_candidate_digest_copy_field (statement : V8PublicStatement) (witness : V8Witness)
    (family : DigestCopyFamily) (limb : Fin 7) :
    ((fullTypedSourceCandidate statement witness).getD
      ((92 + family.sourceFamily.base + limb.val) * 64) 0 : F) =
      (authHashWord (typedSourceFinals statement witness) family.call limb.val : F) := by
  have bound : limb.val < family.sourceFamily.width := by cases family <;> exact limb.isLt
  have result := parent_auth_family_field statement witness family.sourceFamily limb.val bound
  cases family <;> exact result

theorem full_candidate_digest_final_field (statement : V8PublicStatement) (witness : V8Witness)
    (family : DigestCopyFamily) (limb : Fin 7) :
    ((fullTypedSourceCandidate statement witness).getD
      (Poseidon2V8DecoderRefinement.hashFinalIndex family.call limb.val) 0 : F) =
      (authHashWord (typedSourceFinals statement witness) family.call limb.val : F) := by
  have bound : family.call < 125 := by cases family <;> decide
  rw [full_candidate_final_schedule_readback statement witness ⟨family.call,bound⟩ ⟨limb.val,by omega⟩,
      auth_hash_word_readback _ ⟨family.call,bound⟩ limb,
      typed_source_finals_are_actual_schedule statement witness ⟨family.call,bound⟩ limb]

theorem full_candidate_digest_copy_residual_zero (statement : V8PublicStatement) (witness : V8Witness)
    (family : DigestCopyFamily) (limb : Fin 7) :
    actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
      (fullTypedSourceCandidate statement witness) (digestCopyAttempt family limb.val) = 0 := by
  let pub : Nat → F := fun slot => ((encodePublicStatement statement).getD slot 0 : F)
  have constants := actual_csr_zero_one pub
  have negative := actual_tail_negative_one_coefficient pub
  change actualCsrResidual pub _ _ = 0
  simp only [digestCopyAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,constants.1,constants.2,
    negative,one_mul,add_zero,sub_zero]
  rw [full_candidate_digest_copy_field,full_candidate_digest_final_field]
  ring

theorem full_candidate_actual_digest_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (family : DigestCopyFamily) (limb : Fin 7) :
    (exactCsrAttempts[family.start + limb.val]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness)) = some 0 := by
  rw [exact_digest_copy_attempt_lookup,Option.map_some,full_candidate_digest_copy_residual_zero]

def digestCopyIndices : List Nat :=
  ([DigestCopyFamily.statement,.current,.next,.valueLock].flatMap fun family =>
    (List.range 7).map fun limb => family.start + limb)

theorem digest_copy_exact_distinct_count : digestCopyIndices.length = 28 ∧ digestCopyIndices.Nodup := by decide

theorem full_candidate_all_28_digest_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (global : Nat) (selected : global ∈ digestCopyIndices) :
    (exactCsrAttempts[global]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness)) = some 0 := by
  obtain ⟨family,_,member⟩ := List.mem_flatMap.mp selected
  obtain ⟨limb,bound,equal⟩ := List.mem_map.mp member
  rw [← equal]
  exact full_candidate_actual_digest_csr_zero statement witness family ⟨limb,List.mem_range.mp bound⟩

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthDigestCsr
