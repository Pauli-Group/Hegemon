import HegemonCrypto.SmallWoodV8Smz9SourceAuthInitialWords
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies

/-! All actual initialization CSR rows for current/next accumulators and
value lock. The selected rows and coefficients are fixed source tables. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthInitial128
open Hegemon.Transaction
open Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (rawIndex hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9AccumulatorSource
open HegemonCrypto.SmallWood.V8Smz9ValueLockSource
open HegemonCrypto.SmallWood.V8Smz9AuthorizationDigestCopies
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

def accumulatorInitialAttempt (which block lane : Nat) : CsrExecutableAttempt :=
  attempt (18971 + 55 * which + 16 * block + lane) (29 + 2 * which) (16 * block + lane) 0
    (([(hashInitialIndex (98 + 3 * which + block) lane,1)] ++
      (if block = 0 then [] else [(hashFinalIndex (98 + 3 * which + block - 1) lane,158)])) ++
      (if lane < 8 ∧ block * 8 + lane < 23 then
        [(rawIndex (accumulatorInitialRawRow which (block * 8 + lane)),158)] else []))
    (if lane < 8 ∧ block * 8 + lane < 23 then 0 else accumulatorFrameTarget block lane)

def valueLockInitialAttempt (block lane : Nat) : CsrExecutableAttempt :=
  attempt (19081 + 16 * block + lane) 33 (16 * block + lane) 0
    (([(hashInitialIndex (104 + block) lane,1)] ++
      (if block = 0 then [] else [(hashFinalIndex (104 + block - 1) lane,158)])) ++
      (if lane < 8 ∧ block * 8 + lane < 14 then [(rawIndex (138 + block * 8 + lane),158)] else []))
    (if lane < 8 ∧ block * 8 + lane < 14 then 0 else valueLockFrameTarget block lane)

theorem accumulator_initial_chunks_member (which : Fin 2) (block : Fin 3) (lane : Fin 16) :
    accumulatorInitialAttempt which.val block.val lane.val ∈ accumulatorFrameChunks.flatten := by
  fin_cases which <;> fin_cases block <;> fin_cases lane <;> decide

theorem accumulator_initial_exact_lookup (which : Fin 2) (block : Fin 3) (lane : Fin 16) :
    exactCsrAttempts[18971 + 55 * which.val + 16 * block.val + lane.val]? =
      some (accumulatorInitialAttempt which.val block.val lane.val) := by
  obtain ⟨chunk,chunkMember,entry⟩ := List.mem_flatten.mp (accumulator_initial_chunks_member which block lane)
  have member : accumulatorInitialAttempt which.val block.val lane.val ∈ exactCsrAttempts := by
    rw [← csr_chunks_equal_materialized_attempts]
    exact List.mem_flatten.mpr ⟨_,accumulator_frame_chunk_mem_exact chunkMember,entry⟩
  obtain ⟨position,found⟩ := List.getElem?_of_mem member
  have canonical := checkCsr_sound _ _ _ hgv8rp03_csr_check_passes position _ found
  have same : 18971 + 55 * which.val + 16 * block.val + lane.val = position := canonical.1.1
  rw [same]
  exact found

def valueInitialChunks : List (List CsrExecutableAttempt) :=
  [V8Smz9ProgramCanonicalityCsr37.chunk004,V8Smz9ProgramCanonicalityCsr37.chunk005]

theorem value_lock_initial_chunks_member (block : Fin 2) (lane : Fin 16) :
    valueLockInitialAttempt block.val lane.val ∈ valueInitialChunks.flatten := by
  fin_cases block <;> fin_cases lane <;> decide

theorem value_initial_chunk_member (chunk : List CsrExecutableAttempt) (member : chunk ∈ valueInitialChunks) :
    chunk ∈ csrChunks000 := by
  have sectionMember : chunk ∈ V8Smz9ProgramCanonicalityCsr37.chunkList := by
    simp only [valueInitialChunks,List.mem_cons,List.not_mem_nil,or_false] at member
    rcases member with rfl | rfl <;> decide
  exact authorization_csr_chunk_mem_exact sectionMember

theorem value_lock_initial_exact_lookup (block : Fin 2) (lane : Fin 16) :
    exactCsrAttempts[19081 + 16 * block.val + lane.val]? =
      some (valueLockInitialAttempt block.val lane.val) := by
  obtain ⟨chunk,chunkMember,entry⟩ := List.mem_flatten.mp (value_lock_initial_chunks_member block lane)
  have member : valueLockInitialAttempt block.val lane.val ∈ exactCsrAttempts := by
    rw [← csr_chunks_equal_materialized_attempts]
    exact List.mem_flatten.mpr ⟨_,value_initial_chunk_member _ chunkMember,entry⟩
  obtain ⟨position,found⟩ := List.getElem?_of_mem member
  have canonical := checkCsr_sound _ _ _ hgv8rp03_csr_check_passes position _ found
  have same : 19081 + 16 * block.val + lane.val = position := canonical.1.1
  rw [same]
  exact found

theorem actual_auth_initial_negative (pub : Nat → F) : actualCsrCoefficients pub 158 = -1 := by
  simpa using (actual_dense_negative_coefficients pub).1 0 (by decide)

theorem actual_accumulator_frame_coefficient (pub : Nat → F) (block lane : Nat) :
    actualCsrCoefficients pub (accumulatorFrameTarget block lane) =
      (accumulatorFrameConstant block lane : F) :=
  actual_csr_node_field_equation pub (exact_accumulator_frame_nodes block lane)

theorem actual_value_lock_frame_coefficient (pub : Nat → F) (block : Fin 2) (lane : Fin 16) :
    actualCsrCoefficients pub (valueLockFrameTarget block.val lane.val) =
      (valueLockFrameConstant block.val lane.val : F) :=
  actual_csr_node_field_equation pub (value_lock_frame_target block lane)

theorem actual_accumulator_initial_residual (pub : Nat → F) (packed : List Nat) (which block lane : Nat) :
    actualCsrResidual pub packed (accumulatorInitialAttempt which block lane) =
      (packed.getD (hashInitialIndex (98 + 3 * which + block) lane) 0 : F) -
      (if block = 0 then 0 else (packed.getD (hashFinalIndex (98 + 3 * which + block - 1) lane) 0 : F)) -
      (if lane < 8 ∧ block * 8 + lane < 23 then
        (packed.getD (rawIndex (accumulatorInitialRawRow which (block * 8 + lane))) 0 : F)
       else actualCsrCoefficients pub (accumulatorFrameTarget block lane)) := by
  by_cases first : block = 0
  · subst block
    by_cases rate : lane < 8 ∧ lane < 23 <;>
      simp [accumulatorInitialAttempt,actualCsrResidual,actualCsrTerms,attempt,
        rate,(actual_csr_zero_one pub).1,(actual_csr_zero_one pub).2,
        actual_auth_initial_negative pub,sub_eq_add_neg,add_assoc]
  · by_cases rate : lane < 8 ∧ block * 8 + lane < 23 <;>
      simp [accumulatorInitialAttempt,actualCsrResidual,actualCsrTerms,attempt,
        first,rate,(actual_csr_zero_one pub).1,(actual_csr_zero_one pub).2,
        actual_auth_initial_negative pub,sub_eq_add_neg,add_assoc]

theorem actual_value_lock_initial_residual (pub : Nat → F) (packed : List Nat) (block lane : Nat) :
    actualCsrResidual pub packed (valueLockInitialAttempt block lane) =
      (packed.getD (hashInitialIndex (104 + block) lane) 0 : F) -
      (if block = 0 then 0 else (packed.getD (hashFinalIndex (104 + block - 1) lane) 0 : F)) -
      (if lane < 8 ∧ block * 8 + lane < 14 then
        (packed.getD (rawIndex (138 + block * 8 + lane)) 0 : F)
       else actualCsrCoefficients pub (valueLockFrameTarget block lane)) := by
  by_cases first : block = 0
  · subst block
    by_cases rate : lane < 8 ∧ lane < 14 <;>
      simp [valueLockInitialAttempt,actualCsrResidual,actualCsrTerms,attempt,
        rate,(actual_csr_zero_one pub).1,(actual_csr_zero_one pub).2,
        actual_auth_initial_negative pub,sub_eq_add_neg]
  · by_cases rate : lane < 8 ∧ block * 8 + lane < 14 <;>
      simp [valueLockInitialAttempt,actualCsrResidual,actualCsrTerms,attempt,
        first,rate,(actual_csr_zero_one pub).1,(actual_csr_zero_one pub).2,
        actual_auth_initial_negative pub,sub_eq_add_neg,add_assoc]

theorem full_candidate_accumulator_initial_residual_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F)
    (which : Fin 2) (block : Fin 3) (lane : Fin 16) :
    actualCsrResidual pub (fullTypedSourceCandidate statement witness)
      (accumulatorInitialAttempt which.val block.val lane.val) = 0 := by
  rw [actual_accumulator_initial_residual,full_candidate_accumulator_initial_field statement witness valid which block lane]
  by_cases rate : lane.val < 8 ∧ block.val * 8 + lane.val < 23
  · rw [if_pos rate,if_pos rate,full_candidate_accumulator_source_word statement witness valid which ⟨_,rate.2⟩]
    ring
  · rw [if_neg rate,if_neg rate,actual_accumulator_frame_coefficient]
    ring

theorem full_candidate_value_lock_initial_residual_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (block : Fin 2) (lane : Fin 16) :
    actualCsrResidual pub (fullTypedSourceCandidate statement witness)
      (valueLockInitialAttempt block.val lane.val) = 0 := by
  rw [actual_value_lock_initial_residual,full_candidate_value_lock_initial_field statement witness valid block lane]
  by_cases rate : lane.val < 8 ∧ block.val * 8 + lane.val < 14
  · rw [if_pos rate,if_pos rate]
    have address : 138 + block.val * 8 + lane.val = 138 + (block.val * 8 + lane.val) := by omega
    rw [address,full_candidate_value_lock_source_word statement witness valid ⟨_,rate.2⟩]
    ring
  · rw [if_neg rate,if_neg rate,actual_value_lock_frame_coefficient pub block lane]
    ring

def authInitial128Index (index : Nat) : Nat :=
  if index < 96 then 18971 + 55 * (index / 48) + index % 48 else 19081 + (index - 96)

theorem auth_initial_exact_distinct_count :
    ((List.range 128).map authInitial128Index).length = 128 ∧
      ((List.range 128).map authInitial128Index).Nodup := by decide

theorem full_candidate_actual_all128_auth_initial_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (index : Fin 128) :
    (exactCsrAttempts[authInitial128Index index.val]?).map
      (actualCsrResidual pub (fullTypedSourceCandidate statement witness)) = some 0 := by
  by_cases accumulator : index.val < 96
  · have split : 18971 + 55 * (index.val / 48) + index.val % 48 =
        18971 + 55 * (index.val / 48) + 16 * ((index.val % 48) / 16) + (index.val % 48) % 16 := by omega
    rw [authInitial128Index,if_pos accumulator,split,
      accumulator_initial_exact_lookup ⟨index.val / 48,by omega⟩
        ⟨(index.val % 48) / 16,by omega⟩ ⟨(index.val % 48) % 16,by omega⟩,
      Option.map_some,full_candidate_accumulator_initial_residual_zero statement witness valid]
  · have split : 19081 + (index.val - 96) =
        19081 + 16 * ((index.val - 96) / 16) + (index.val - 96) % 16 := by omega
    rw [authInitial128Index,if_neg accumulator,split,
      value_lock_initial_exact_lookup ⟨(index.val - 96) / 16,by omega⟩ ⟨(index.val - 96) % 16,by omega⟩,
      Option.map_some,full_candidate_value_lock_initial_residual_zero statement witness valid]

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthInitial128
