import HegemonCrypto.SmallWoodV8Smz9SourceInlineRoots
import HegemonCrypto.SmallWoodV8Smz9SourceAuthRootInputs
import HegemonCrypto.SmallWoodV8Smz9SourceAuthDigestCsr
import Mathlib.Tactic.LinearCombination

/-! Exact inline-policy bindings and three disjoint padding runs on the
unchanged full typed constructor. These are raw CSR equations only. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceInlinePolicy192
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Poseidon2V8DecoderRefinement (rawIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceInlineRows
open HegemonCrypto.SmallWood.V8Smz9SourceInlineRoots
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRootInputs
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField_eq_packedWord)
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceAuthDigestCsr
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

def inlinePolicyAttempt (index : Nat) : CsrExecutableAttempt :=
  let limb := index / 3
  attempt (18779 + index) 27 index 0
    (if index % 3 = 0 then [(17920 + limb, 1), (rawIndex (138 + limb), 158)]
     else if index % 3 = 1 then [(17984 + limb, 1), (hashFinalIndex 97 limb, 158)]
     else [(18048 + limb, 1), (rawIndex 93, 158), (rawIndex 94, 158)]) 0

def inlinePolicyPaddingAttempt (index : Nat) : CsrExecutableAttempt :=
  attempt (18800 + index) 28 index 0 [(17927 + 64 * (index / 57) + index % 57, 1)] 0

def inlinePolicyChunk (global : Nat) : List CsrExecutableAttempt :=
  if global < 18784 then V8Smz9ProgramCanonicalityCsr36.chunk010
  else if global < 18816 then V8Smz9ProgramCanonicalityCsr36.chunk011
  else if global < 18848 then V8Smz9ProgramCanonicalityCsr36.chunk012
  else if global < 18880 then V8Smz9ProgramCanonicalityCsr36.chunk013
  else if global < 18912 then V8Smz9ProgramCanonicalityCsr36.chunk014
  else if global < 18944 then V8Smz9ProgramCanonicalityCsr36.chunk015
  else V8Smz9ProgramCanonicalityCsr37.chunk000

theorem inline_policy_chunk_member (global : Nat) :
    inlinePolicyChunk global ∈ csrChunks000 := by
  apply digest_csr_chunks036_member
  unfold inlinePolicyChunk
  split_ifs
  all_goals decide

theorem inline_policy_attempt_member (index : Fin 21) :
    inlinePolicyAttempt index.val ∈ inlinePolicyChunk (18779 + index.val) := by
  fin_cases index <;> decide

theorem inline_policy_padding_member (index : Fin 171) :
    inlinePolicyPaddingAttempt index.val ∈ inlinePolicyChunk (18800 + index.val) := by
  fin_cases index <;> decide

theorem inline_policy_exact_entry (entry : CsrExecutableAttempt)
    (member : entry ∈ inlinePolicyChunk entry.globalIndex) :
    exactCsrAttempts[entry.globalIndex]? = some entry := by
  have allMember : entry ∈ exactCsrAttempts := by
    rw [← csr_chunks_equal_materialized_attempts]
    exact List.mem_flatten.mpr ⟨_,inline_policy_chunk_member _,member⟩
  obtain ⟨position,found⟩ := List.getElem?_of_mem allMember
  have canonical := checkCsr_sound _ _ _ hgv8rp03_csr_check_passes position _ found
  rw [canonical.1.1]
  exact found

theorem inline_policy_attempt_lookup (index : Fin 21) :
    exactCsrAttempts[18779 + index.val]? = some (inlinePolicyAttempt index.val) :=
  inline_policy_exact_entry _ (inline_policy_attempt_member index)

theorem inline_policy_padding_attempt_lookup (index : Fin 171) :
    exactCsrAttempts[18800 + index.val]? = some (inlinePolicyPaddingAttempt index.val) :=
  inline_policy_exact_entry _ (inline_policy_padding_member index)

theorem actual_negative_one_158 (pub : Nat → F) : actualCsrCoefficients pub 158 = -1 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[158]? = some (.sub 0 1) by decide)
  simpa only [expressionField,(actual_csr_zero_one pub).1,
    (actual_csr_zero_one pub).2,zero_sub] using equation

theorem full_candidate_inline_field (statement : V8PublicStatement) (witness : V8Witness)
    (row : Fin 31) (lane : Fin 64) :
    ((fullTypedSourceCandidate statement witness).getD ((252 + row.val) * 64 + lane.val) 0 : F) =
      (inlineCell (typedLiveInitialStates statement witness) witness row.val lane.val : F) := by
  have h := constructed_inline_lane_readback statement witness
    (typedLiveInitialStates statement witness) (typedSourceTail statement witness) row lane
  rw [laneField_eq_packedWord _ _ _ (by omega)] at h
  exact h

theorem full_candidate_inline_bridge_fields (statement : V8PublicStatement) (witness : V8Witness)
    (limb : Fin 7) :
    ((fullTypedSourceCandidate statement witness).getD (17920 + limb.val) 0 : F) =
      ((fullTypedSourceCandidate statement witness).getD (rawIndex (138 + limb.val)) 0 : F) ∧
    ((fullTypedSourceCandidate statement witness).getD (17984 + limb.val) 0 : F) =
      ((fullTypedSourceCandidate statement witness).getD (hashFinalIndex 97 limb.val) 0 : F) ∧
    ((fullTypedSourceCandidate statement witness).getD (18048 + limb.val) 0 : F) =
      ((fullTypedSourceCandidate statement witness).getD (rawIndex 93) 0 : F) +
      ((fullTypedSourceCandidate statement witness).getD (rawIndex 94) 0 : F) := by
  have h28 := full_candidate_inline_field statement witness ⟨28,by decide⟩ ⟨limb.val,by omega⟩
  have h29 := full_candidate_inline_field statement witness ⟨29,by decide⟩ ⟨limb.val,by omega⟩
  have h30 := full_candidate_inline_field statement witness ⟨30,by decide⟩ ⟨limb.val,by omega⟩
  simp only [inlineCell,show ¬28 < 28 by decide,show ¬29 < 28 by decide,
    show ¬30 < 28 by decide,if_false,limb.isLt,if_true,
    show ¬29 = 28 by decide,show ¬30 = 28 by decide,show ¬30 = 29 by decide] at h28 h29 h30
  have policy := full_candidate_auth_family statement witness .policy limb.val limb.isLt ⟨0,by decide⟩
  have mode1 := full_candidate_auth_family statement witness .mode 1 (by decide) ⟨0,by decide⟩
  have mode2 := full_candidate_auth_family statement witness .mode 2 (by decide) ⟨0,by decide⟩
  simp only [AuthFamily.base] at policy mode1 mode2
  rw [laneField_eq_packedWord _ _ _ (by omega)] at policy mode1 mode2
  simp only [V8Smz9SemanticDecoder.packedWord,Nat.add_zero] at policy mode1 mode2
  have policyAddress : (92 + 46 + limb.val) * 64 = rawIndex (138 + limb.val) := by
    simp only [rawIndex,Poseidon2V8DecoderRefinement.rawRowStart,
      Poseidon2V8DecoderRefinement.packingFactor,Nat.zero_add]
  rw [policyAddress] at policy
  have final := constructed_auth_final_at_hash_index statement witness
    (typedLiveInitialStates statement witness) (typedSourceTail statement witness) ⟨97,by decide⟩ limb
  have hash := auth_hash_word_readback (typedSourceFinals statement witness) ⟨97,by decide⟩ limb
  change authHashWord (typedSourceFinals statement witness) 97 limb.val =
    callFinalWord (typedLiveInitialStates statement witness) 97 limb.val at hash
  change ((fullTypedSourceCandidate statement witness).getD (rawIndex (138 + limb.val)) 0 : F) =
    (authPolicyWord witness.authorization (typedSourceFinals statement witness) limb.val : F) at policy
  change ((fullTypedSourceCandidate statement witness).getD (rawIndex 93) 0 : F) =
    (authModeFlag witness.authorization.mode 1 : F) at mode1
  change ((fullTypedSourceCandidate statement witness).getD (rawIndex 94) 0 : F) =
    (authModeFlag witness.authorization.mode 2 : F) at mode2
  change (fullTypedSourceCandidate statement witness).getD (hashFinalIndex 97 limb.val) 0 =
    callFinalWord (typedLiveInitialStates statement witness) 97 limb.val at final
  refine ⟨?_,?_,?_⟩
  · rw [policy]
    simpa only [policyWord,authPolicyWord,hash] using h28
  · rw [final]
    exact h29
  · rw [mode1,mode2]
    rw [h30]
    cases modeEq : witness.authorization.mode <;> norm_num [nonSingle,modeEq,authModeFlag,authBit] <;> decide

theorem full_candidate_inline_policy_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (pub : Nat → F) (index : Fin 21) :
    actualCsrResidual pub (fullTypedSourceCandidate statement witness) (inlinePolicyAttempt index.val) = 0 := by
  have fields := full_candidate_inline_bridge_fields statement witness ⟨index.val / 3,by omega⟩
  unfold inlinePolicyAttempt
  split_ifs
  all_goals simp only [attempt,actualCsrResidual,actualCsrTerms,List.map_cons,List.map_nil,
    List.sum_cons,List.sum_nil,(actual_csr_zero_one pub).1,(actual_csr_zero_one pub).2,
    actual_negative_one_158,one_mul,neg_one_mul,add_zero]
  · linear_combination fields.1
  · linear_combination fields.2.1
  · linear_combination fields.2.2

theorem full_candidate_inline_policy_padding_zero (statement : V8PublicStatement) (witness : V8Witness)
    (pub : Nat → F) (index : Fin 171) :
    actualCsrResidual pub (fullTypedSourceCandidate statement witness)
      (inlinePolicyPaddingAttempt index.val) = 0 := by
  have h := full_candidate_inline_field statement witness
    ⟨28 + index.val / 57,by omega⟩ ⟨7 + index.val % 57,by omega⟩
  have address : (252 + (28 + index.val / 57)) * 64 + (7 + index.val % 57) =
      17927 + 64 * (index.val / 57) + index.val % 57 := by omega
  rw [address] at h
  simp only [inlineCell,if_neg (by omega : ¬28 + index.val / 57 < 28),
    if_neg (by omega : ¬7 + index.val % 57 < 7),Nat.cast_zero] at h
  simpa only [inlinePolicyPaddingAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,(actual_csr_zero_one pub).1,
    (actual_csr_zero_one pub).2,one_mul,add_zero,sub_zero] using h

def inlinePolicy192Indices : List Nat := (List.range 192).map (18779 + ·)
theorem inline_policy192_count : inlinePolicy192Indices.length = 192 := by decide
theorem inline_policy192_nodup : inlinePolicy192Indices.Nodup := by decide

theorem full_candidate_inline_policy192_indexed (statement : V8PublicStatement) (witness : V8Witness)
    (pub : Nat → F) (index : Fin 192) :
    (exactCsrAttempts[18779 + index.val]?).map
      (actualCsrResidual pub (fullTypedSourceCandidate statement witness)) = some 0 := by
  by_cases low : index.val < 21
  · rw [inline_policy_attempt_lookup ⟨index.val,low⟩,Option.map_some]
    exact congrArg some (full_candidate_inline_policy_csr_zero statement witness pub ⟨index.val,low⟩)
  · have bound : index.val - 21 < 171 := by omega
    have address : 18779 + index.val = 18800 + (index.val - 21) := by omega
    rw [address,inline_policy_padding_attempt_lookup ⟨index.val - 21,bound⟩,Option.map_some]
    exact congrArg some (full_candidate_inline_policy_padding_zero statement witness pub ⟨index.val - 21,bound⟩)

theorem full_candidate_inline_policy192_results (statement : V8PublicStatement) (witness : V8Witness)
    (pub : Nat → F) :
    inlinePolicy192Indices.length = 192 ∧ inlinePolicy192Indices.Nodup ∧
    (inlinePolicy192Indices.map fun global => (exactCsrAttempts[global]?).map
      (actualCsrResidual pub (fullTypedSourceCandidate statement witness))) = List.replicate 192 (some 0) := by
  refine ⟨inline_policy192_count,inline_policy192_nodup,?_⟩
  have equal : (inlinePolicy192Indices.map fun global => (exactCsrAttempts[global]?).map
      (actualCsrResidual pub (fullTypedSourceCandidate statement witness))) =
      inlinePolicy192Indices.map (fun _ => some (0 : F)) := by
    apply List.map_congr_left
    intro global member
    change global ∈ (List.range 192).map (18779 + ·) at member
    obtain ⟨index,bound,equal⟩ := List.mem_map.mp member
    rw [← equal]
    exact full_candidate_inline_policy192_indexed statement witness pub ⟨index,List.mem_range.mp bound⟩
  simpa only [List.map_const',inline_policy192_count] using equal

end
end HegemonCrypto.SmallWood.V8Smz9SourceInlinePolicy192
