import HegemonCrypto.SmallWoodV8Smz9SourceStableRoleCsrReadbacks
import HegemonCrypto.SmallWoodV8Smz9ParentRoleCsrBinding

namespace HegemonCrypto.SmallWood.V8Smz9SourceLiveRoleCsrRoots

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrTable
open HegemonCrypto.SmallWood.V8Smz9SourceRoleCsrFieldTerms
open HegemonCrypto.SmallWood.V8Smz9SourceStableRoleCsrReadbacks
open HegemonCrypto.SmallWood.V8Smz9ParentRoleCsrBinding
open HegemonCrypto.SmallWood.V8Smz9ParentRoleCsrReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

def liveRoleCsrIndices : List Nat := (List.range 210).map (19344 + ·)

theorem live_role_csr_count : liveRoleCsrIndices.length = 210 := by decide
theorem live_role_csr_distinct : liveRoleCsrIndices.Nodup := by
  have chain : liveRoleCsrIndices.IsChain (· < ·) := by decide
  exact (List.isChain_iff_pairwise.mp chain).imp (fun less => Nat.ne_of_lt less)

noncomputable section

theorem full_all_live_role_kernels_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (role : Fin 30) (limb : Fin 7) :
    roleCsrFieldKernel (liveTypedPub statement) (fullSourceField statement witness) role.val limb.val = 0 := by
  by_cases stable : role.val < 21
  · exact full_stable_role_kernel_zero statement witness valid ⟨role.val,stable⟩ limb
  · have offset : role.val = 21 + (role.val - 21) := by omega
    rw [offset]
    exact parent_role_kernel_zero statement witness valid ⟨role.val - 21,by omega⟩ limb

theorem full_actual_live_role_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 210) :
    (exactCsrAttempts[19344 + index.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  have role : index.val / 7 < 30 := by omega
  have limb : index.val % 7 < 7 := Nat.mod_lt _ (by decide)
  have address : 19344 + index.val = 19344 + (index.val / 7) * 7 + index.val % 7 := by omega
  rw [address,actual_global_role_csr_as_field_kernel (liveTypedPub statement)
    (fullTypedSourceCandidate statement witness) ⟨index.val / 7,role⟩ ⟨index.val % 7,limb⟩]
  change some (roleCsrFieldKernel (liveTypedPub statement) (fullSourceField statement witness)
    (index.val / 7) (index.val % 7)) = some 0
  rw [full_all_live_role_kernels_zero statement witness valid ⟨index.val / 7,role⟩ ⟨index.val % 7,limb⟩]

theorem full_candidate_exact_210_live_role_results (statement : V8PublicStatement)
    (witness : V8Witness) (valid : ExactV8RelationSemanticValid statement witness) :
    liveRoleCsrIndices.length = 210 ∧ liveRoleCsrIndices.Nodup ∧
    (liveRoleCsrIndices.map fun global => (exactCsrAttempts[global]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness))) = List.replicate 210 (some 0) := by
  refine ⟨live_role_csr_count,live_role_csr_distinct,?_⟩
  change (liveRoleCsrIndices.map fun global => (exactCsrAttempts[global]?).map
    (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness))) = _
  have each (global : Nat) (member : global ∈ liveRoleCsrIndices) :
      (exactCsrAttempts[global]?).map
        (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
    obtain ⟨index,bound,equal⟩ := List.mem_map.mp member
    rw [←equal]
    exact full_actual_live_role_csr_zero statement witness valid ⟨index,List.mem_range.mp bound⟩
  have equal := List.map_congr_left each
  simpa only [List.map_const',live_role_csr_count] using equal


end
end HegemonCrypto.SmallWood.V8Smz9SourceLiveRoleCsrRoots
