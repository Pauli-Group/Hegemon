import HegemonCrypto.SmallWoodV8Smz9SourceNoteDigestForward
import HegemonCrypto.SmallWoodV8Smz9NoteOutputPublic
import HegemonCrypto.SmallWoodV8Smz9SourceAuthInputSelection
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies

namespace HegemonCrypto.SmallWood.V8Smz9SourceOutputCommitment14
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (hashFinalIndex outputNoteCall)
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceNoteDigestForward
open HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames
open HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
open HegemonCrypto.SmallWood.V8Smz9NoteOutputPublic
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

theorem full_candidate_output_commitment_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (output : Fin 2) (limb : Fin 7) :
    ((fullTypedSourceCandidate statement witness).getD (hashFinalIndex (outputNoteCall output.val + 2) limb.val) 0 : F) =
      ((exactV8NoteCommitment (witness.outputs.getD output.val default).note).getD limb.val 0 : F) := by
  have callBound : outputNoteCall output.val + 2 < 125 := by fin_cases output <;> decide
  rw [full_candidate_final_schedule_readback statement witness ⟨_,callBound⟩ ⟨limb.val,by omega⟩]
  apply congrArg (fun n : Nat => (n : F))
  apply first_seven_readback
  have digest := typed_note_scheduled_digest_exact statement witness valid ⟨2 + output.val,by omega⟩
  have call : noteBridgeCall (2 + output.val) = outputNoteCall output.val := by fin_cases output <;> rfl
  have note : sourceNoteOpening witness (2 + output.val) = (witness.outputs.getD output.val default).note := by
    simp only [sourceNoteOpening,if_neg (by omega : ¬2 + output.val < 2),Nat.add_sub_cancel_left]
  simpa only [call,note] using digest

theorem actual_output_commitment_coefficients (pub : Nat → F) (output : Fin 2) (limb : Fin 7) :
    actualCsrCoefficients pub (6 + output.val) = pub (2 + output.val) ∧
      actualCsrCoefficients pub (289 + 8 * output.val + limb.val) =
        pub (2 + output.val) * pub (18 + 7 * output.val + limb.val) := by
  have nodes := exact_output_commitment_nodes output limb
  have flag := actual_csr_node_field_equation pub nodes.1
  have word := actual_csr_node_field_equation pub nodes.2.1
  have target := actual_csr_node_field_equation pub nodes.2.2
  exact ⟨flag,by simpa only [expressionField,flag,word] using target⟩

theorem actual_output_commitment_residual (pub : Nat → F) (packed : List Nat) (output : Fin 2) (limb : Fin 7) :
    actualCsrResidual pub packed (outputCommitmentAttempt output.val limb.val) =
      pub (2 + output.val) * ((packed.getD (hashFinalIndex (outputNoteCall output.val + 2) limb.val) 0 : F) -
        pub (18 + 7 * output.val + limb.val)) := by
  simp only [outputCommitmentAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,add_zero,
    (actual_output_commitment_coefficients pub output limb).1,
    (actual_output_commitment_coefficients pub output limb).2]
  ring

theorem full_candidate_output_commitment_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (output : Fin 2) (limb : Fin 7) :
    actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
      (fullTypedSourceCandidate statement witness) (outputCommitmentAttempt output.val limb.val) = 0 := by
  rw [actual_output_commitment_residual,encoded_output_flag statement valid.1 output.isLt]
  have flag := HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical.boolean_getD
    statement.outputFlags valid.1.2.2.2.1 output.val
  change flagAt statement.outputFlags output.val = 0 ∨ flagAt statement.outputFlags output.val = 1 at flag
  rcases flag with inactive | active
  · rw [inactive,Nat.cast_zero,zero_mul]
  · have link : exactV8NoteCommitment (witness.outputs.getD output.val default).note =
        digestAt statement.commitments output.val := valid.2.2.1.2.1 output.val output.isLt active
    rw [full_candidate_output_commitment_word statement witness valid output limb,link,
      encoded_public_commitment_word statement valid.1 output limb,sub_self,mul_zero]

theorem output_commitment_exact_lookup (output : Fin 2) (limb : Fin 7) :
    exactCsrAttempts[18454 + 7 * output.val + limb.val]? = some (outputCommitmentAttempt output.val limb.val) :=
  exact_attempt_lookup _ (exact_output_commitment_attempts output limb)

theorem full_candidate_actual_output_commitment14_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 14) :
    (exactCsrAttempts[18454 + index.val]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness)) = some 0 := by
  have address : 18454 + index.val = 18454 + 7 * (index.val / 7) + index.val % 7 := by omega
  rw [address,output_commitment_exact_lookup ⟨index.val / 7,by omega⟩ ⟨index.val % 7,by omega⟩,
    Option.map_some,full_candidate_output_commitment_zero statement witness valid]

end
end HegemonCrypto.SmallWood.V8Smz9SourceOutputCommitment14
