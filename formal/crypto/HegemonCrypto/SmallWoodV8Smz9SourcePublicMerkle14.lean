import HegemonCrypto.SmallWoodV8Smz9SourceMerkleFoldForward
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies
import HegemonCrypto.SmallWoodV8Smz9SourceAuthInputSelection
import HegemonCrypto.SmallWoodV8Smz9InputMerklePublic

namespace HegemonCrypto.SmallWood.V8Smz9SourcePublicMerkle14
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (hashFinalIndex inputMerkleCall)
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleFoldForward
open HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
open HegemonCrypto.SmallWood.V8Smz9SourceAuthInputSelection
open HegemonCrypto.SmallWood.V8Smz9InputMerklePublic
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem full_candidate_active_merkle_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (limb : Fin 7)
    (active : flagAt statement.inputFlags input.val = 1) :
    ((fullTypedSourceCandidate statement witness).getD (hashFinalIndex (inputMerkleCall input.val 31) limb.val) 0 : F) =
      (statement.merkleRoot.getD limb.val 0 : F) := by
  have callBound : inputMerkleCall input.val 31 < 125 := by fin_cases input <;> decide
  rw [full_candidate_final_schedule_readback statement witness ⟨_,callBound⟩ ⟨limb.val,by omega⟩]
  apply congrArg (fun n : Nat => (n : F))
  apply first_seven_readback
  have digest := typed_merkle_scheduled_digest_exact statement witness valid input
  exact digest.trans (valid.2.2.1.1 input.val input.isLt active).1

theorem actual_public_merkle_coefficients (pub : Nat → F) (input : Fin 2) (limb : Fin 7) :
    actualCsrCoefficients pub (4 + input.val) = pub input.val ∧
      actualCsrCoefficients pub (199 + 75 * input.val + limb.val) =
        pub input.val * pub (47 + limb.val) := by
  have nodes := exact_input_root_nodes input limb
  have flag := actual_csr_node_field_equation pub nodes.1
  have word := actual_csr_node_field_equation pub nodes.2.1
  have target := actual_csr_node_field_equation pub nodes.2.2
  exact ⟨flag,by simpa only [expressionField,flag,word] using target⟩

theorem actual_public_merkle_residual (pub : Nat → F) (packed : List Nat) (input : Fin 2) (limb : Fin 7) :
    actualCsrResidual pub packed (inputRootAttempt input.val limb.val) =
      pub input.val * ((packed.getD (hashFinalIndex (inputMerkleCall input.val 31) limb.val) 0 : F) -
        pub (47 + limb.val)) := by
  simp only [inputRootAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,add_zero,
    (actual_public_merkle_coefficients pub input limb).1,
    (actual_public_merkle_coefficients pub input limb).2]
  ring

theorem full_candidate_public_merkle_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (limb : Fin 7) :
    actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
      (fullTypedSourceCandidate statement witness) (inputRootAttempt input.val limb.val) = 0 := by
  rw [actual_public_merkle_residual,encoded_input_flag statement valid.1 input.isLt]
  rcases typed_input_flag_boolean statement witness valid input with inactive | active
  · rw [inactive,Nat.cast_zero,zero_mul]
  · rw [full_candidate_active_merkle_word statement witness valid input limb active,
      encoded_merkle_root_word statement valid.1 limb.isLt,sub_self,mul_zero]

theorem public_merkle_exact_lookup (input : Fin 2) (limb : Fin 7) :
    exactCsrAttempts[18286 + 7 * input.val + limb.val]? = some (inputRootAttempt input.val limb.val) :=
  exact_attempt_lookup _ (exact_input_root_attempt input limb)

theorem full_candidate_actual_public_merkle14_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 14) :
    (exactCsrAttempts[18286 + index.val]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness)) = some 0 := by
  have address : 18286 + index.val = 18286 + 7 * (index.val / 7) + index.val % 7 := by omega
  rw [address,public_merkle_exact_lookup ⟨index.val / 7,by omega⟩ ⟨index.val % 7,by omega⟩,
    Option.map_some,full_candidate_public_merkle_zero statement witness valid]

end
end HegemonCrypto.SmallWood.V8Smz9SourcePublicMerkle14
