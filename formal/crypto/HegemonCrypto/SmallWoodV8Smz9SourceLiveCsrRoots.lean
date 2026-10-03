import HegemonCrypto.SmallWoodV8Smz9SourceSimpleLiveCsrRoots

namespace HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrRoots

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrTable
open HegemonCrypto.SmallWood.V8Smz9SourceSimpleLiveCsrRoots
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

def simpleLiveCsrFamilies : List LiveCsrFamily :=
  [.disabled,.compatibility,.issuer,.burn,.scalar,.direction,.assetBits]
def simpleLiveCsrIndices : List Nat :=
  simpleLiveCsrFamilies.flatMap fun family => (List.range family.count).map (family.start + ·)

theorem simple_live_csr_count : simpleLiveCsrIndices.length = 135 := by decide
theorem simple_live_csr_distinct : simpleLiveCsrIndices.Nodup := by
  have chain : simpleLiveCsrIndices.IsChain (· < ·) := by decide
  exact (List.isChain_iff_pairwise.mp chain).imp (fun less => Nat.ne_of_lt less)

noncomputable section

theorem full_candidate_expected_simple_live_csr_zero (statement : V8PublicStatement)
    (witness : V8Witness) (valid : ExactV8RelationSemanticValid statement witness)
    (family : LiveCsrFamily) (simple : family ∈ simpleLiveCsrFamilies) (index : Fin family.count) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (expectedLiveCsrAttempt family index.val) = 0 := by
  cases family
  · exact full_disabled_csr_zero statement witness valid index
  · exact full_compatibility_csr_zero statement witness valid index
  · exact full_issuer_csr_zero statement witness valid index
  · exact full_burn_csr_zero statement witness valid index
  · exact full_scalar_csr_zero statement witness valid index
  · exact full_direction_csr_zero statement witness valid index
  · exact full_asset_bits_csr_zero statement witness valid index
  · simp [simpleLiveCsrFamilies] at simple

theorem full_candidate_actual_simple_live_csr_zero (statement : V8PublicStatement)
    (witness : V8Witness) (valid : ExactV8RelationSemanticValid statement witness)
    (family : LiveCsrFamily) (simple : family ∈ simpleLiveCsrFamilies) (index : Fin family.count) :
    (exactCsrAttempts[family.start + index.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  rw [actual_live_csr_entry,Option.map_some,
    full_candidate_expected_simple_live_csr_zero statement witness valid family simple index]

theorem full_candidate_all_simple_live_csr_zero (statement : V8PublicStatement)
    (witness : V8Witness) (valid : ExactV8RelationSemanticValid statement witness)
    (global : Nat) (selected : global ∈ simpleLiveCsrIndices) :
    (exactCsrAttempts[global]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  obtain ⟨family,member,indices⟩ := List.mem_flatMap.mp selected
  obtain ⟨index,bound,equal⟩ := List.mem_map.mp indices
  rw [←equal]
  exact full_candidate_actual_simple_live_csr_zero statement witness valid family member
    ⟨index,List.mem_range.mp bound⟩

theorem full_candidate_exact_135_live_csr_results (statement : V8PublicStatement)
    (witness : V8Witness) (valid : ExactV8RelationSemanticValid statement witness) :
    simpleLiveCsrIndices.length = 135 ∧ simpleLiveCsrIndices.Nodup ∧
    (simpleLiveCsrIndices.map fun global => (exactCsrAttempts[global]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness))) = List.replicate 135 (some 0) := by
  refine ⟨simple_live_csr_count,simple_live_csr_distinct,?_⟩
  have equal := List.map_congr_left (fun global selected =>
    full_candidate_all_simple_live_csr_zero statement witness valid global selected)
  change (simpleLiveCsrIndices.map fun global => (exactCsrAttempts[global]?).map
    (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness))) = _
  simpa only [List.map_const',simple_live_csr_count] using equal

theorem disabled_nonzero_source_rejected : (1 : F) * 1 - 0 ≠ 0 := by norm_num


end
end HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrRoots
