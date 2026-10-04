import HegemonCrypto.SmallWoodV8Smz9SourceStableRangeNatural
import HegemonCrypto.SmallWoodV8Smz9SourceStableRangeCoefficients
import HegemonCrypto.SmallWoodV8Smz9SourceStableLiveRoleCsr
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableRange66
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeDigits
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeNatural
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr (liveTypedPub)
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies (exact_attempt_lookup)
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (packedWord)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem actual_even_range_residual (pub : Nat → F) (packed : List Nat)
    (spec : StableEvenRange) (valid : spec.Valid) :
    actualCsrResidual pub packed (stableEvenAttempt spec) =
      (if spec.isPublic then pub spec.sourceIndex else (packed.getD spec.sourceIndex 0 : F))-
        (stableEvenNatural packed spec : F) := by
  unfold actualCsrResidual stableEvenAttempt
  simp only [attempt]
  by_cases publicCase : spec.isPublic=true
  · simp only [if_pos publicCase,List.nil_append]
    rw [actual_stable_even_negative_terms pub packed spec valid,
      actual_stable_even_public_target pub spec valid publicCase]
    ring
  · have target : spec.targetRoot=0 := by simpa only [if_neg publicCase] using valid.2.2.2.2
    simp only [if_neg publicCase,List.cons_append,List.nil_append]
    rw [actual_csr_terms_cons,(actual_csr_zero_one pub).2,one_mul,
      actual_stable_even_negative_terms pub packed spec valid,target,(actual_csr_zero_one pub).1]
    ring

theorem actual_odd_range_residual (pub : Nat → F) (packed : List Nat)
    (spec : StableOddRange) (valid : spec.Valid) :
    actualCsrResidual pub packed (stableOddAttempt spec) =
      (if spec.isPublic then pub spec.sourceIndex else (packed.getD spec.sourceIndex 0 : F))-
        (stableOddNatural packed spec : F) := by
  unfold actualCsrResidual stableOddAttempt
  simp only [attempt]
  by_cases publicCase : spec.isPublic=true
  · simp only [if_pos publicCase,List.nil_append]
    rw [actual_stable_odd_negative_terms pub packed spec valid,
      actual_stable_odd_public_target pub spec valid publicCase]
    ring
  · have target : spec.targetRoot=0 := by simpa only [if_neg publicCase] using valid.2.2.2.2.2.2.2
    simp only [if_neg publicCase,List.cons_append,List.nil_append]
    rw [actual_csr_terms_cons,(actual_csr_zero_one pub).2,one_mul,
      actual_stable_odd_negative_terms pub packed spec valid,target,(actual_csr_zero_one pub).1]
    ring

theorem full_candidate_even_attempt_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 46) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (stableEvenAttempt (sourceEvenSpec index))=0 := by
  have dataValid := exact_stable_even_ranges.1 _ (source_even_spec_properties index).2.2.2
  rw [actual_even_range_residual _ _ _ dataValid]
  have source := full_candidate_even_source statement witness valid index
  have fieldSource : (if (sourceEvenSpec index).isPublic then liveTypedPub statement (sourceEvenSpec index).sourceIndex
        else ((fullTypedSourceCandidate statement witness).getD (sourceEvenSpec index).sourceIndex 0 : F)) =
      ((sourceRangeEntry statement witness (sourceEvenSpec index).localIndex).1 : F) := by
    rw [←source]
    simp only [stableEvenSource,liveTypedPub,packedWord]
    split_ifs <;> rfl
  rw [fieldSource,full_candidate_even_natural statement witness valid index,sub_self]

theorem full_candidate_odd_attempt_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 20) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (stableOddAttempt (sourceOddSpec index))=0 := by
  have dataValid := exact_stable_odd_ranges.1 _ (source_odd_spec_properties index).2.2.2.2
  rw [actual_odd_range_residual _ _ _ dataValid]
  have source := full_candidate_odd_source statement witness valid index
  have fieldSource : (if (sourceOddSpec index).isPublic then liveTypedPub statement (sourceOddSpec index).sourceIndex
        else ((fullTypedSourceCandidate statement witness).getD (sourceOddSpec index).sourceIndex 0 : F)) =
      ((sourceRangeEntry statement witness (sourceOddSpec index).localIndex).1 : F) := by
    rw [←source]
    simp only [stableOddSource,liveTypedPub,packedWord]
    split_ifs <;> rfl
  rw [fieldSource,full_candidate_odd_natural statement witness valid index,sub_self]

theorem source_even_spec_local_index (index : Fin 46) :
    (sourceEvenSpec index).localIndex=if index.val<7 then index.val else index.val+20 := by
  fin_cases index <;> decide

theorem full_candidate_actual_range66_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 66) :
    (exactCsrAttempts[20192+index.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness))=some 0 := by
  by_cases small : index.val<7
  · let evenIndex : Fin 46 := ⟨index.val,by omega⟩
    have localIndex : (sourceEvenSpec evenIndex).localIndex=index.val := by
      rw [source_even_spec_local_index,if_pos small]
    have found := exact_attempt_lookup _ (exact_stable_even_ranges.2 _ (source_even_spec_properties evenIndex).2.2.2)
    change exactCsrAttempts[20192+(sourceEvenSpec evenIndex).localIndex]? = _ at found
    rw [localIndex] at found
    simp only [found,Option.map_some,full_candidate_even_attempt_zero statement witness valid evenIndex]
  · by_cases high : 27 ≤ index.val
    · let evenIndex : Fin 46 := ⟨index.val-20,by omega⟩
      have localIndex : (sourceEvenSpec evenIndex).localIndex=index.val := by
        rw [source_even_spec_local_index,if_neg (show ¬evenIndex.val<7 by dsimp [evenIndex]; omega)]
        dsimp [evenIndex]; omega
      have found := exact_attempt_lookup _ (exact_stable_even_ranges.2 _ (source_even_spec_properties evenIndex).2.2.2)
      change exactCsrAttempts[20192+(sourceEvenSpec evenIndex).localIndex]? = _ at found
      rw [localIndex] at found
      simp only [found,Option.map_some,full_candidate_even_attempt_zero statement witness valid evenIndex]
    · let oddIndex : Fin 20 := ⟨index.val-7,by omega⟩
      have localIndex : (sourceOddSpec oddIndex).localIndex=index.val := by
        rw [(source_odd_spec_properties oddIndex).1]
        dsimp [oddIndex]; omega
      have found := exact_attempt_lookup _ (exact_stable_odd_ranges.2 _ (source_odd_spec_properties oddIndex).2.2.2.2)
      change exactCsrAttempts[20192+(sourceOddSpec oddIndex).localIndex]? = _ at found
      rw [localIndex] at found
      simp only [found,Option.map_some,full_candidate_odd_attempt_zero statement witness valid oddIndex]

end
end HegemonCrypto.SmallWood.V8Smz9SourceStableRange66
