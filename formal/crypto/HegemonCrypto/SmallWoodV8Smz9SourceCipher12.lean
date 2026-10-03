import HegemonCrypto.SmallWoodV8Smz9SourceBase7
import HegemonCrypto.SmallWoodV8Smz9SourceEarlyCiphertextRoots

/-! Twelve actual ciphertext-copy CSR rows. Their public value is installed
by the same full source constructor, without a typed-validity premise. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceCipher12
open Hegemon.Transaction
open Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceBase7
open HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField_eq_packedWord)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

def ciphertextBridgeAttempt (output limb : Nat) : CsrExecutableAttempt :=
  attempt (15653 + 6 * output + limb) 3 (6 * output + limb) 0
    [((70 + 12 * output + limb) * 64,1)] (36 + 6 * output + limb)

theorem ciphertext_bridge_chunk_member (output : Fin 2) (limb : Fin 6) :
    ciphertextBridgeAttempt output.val limb.val ∈ V8Smz9ProgramCanonicalityCsr30.chunk009 := by
  fin_cases output <;> fin_cases limb <;> decide

theorem ciphertext_bridge_chunk_in_complete :
    V8Smz9ProgramCanonicalityCsr30.chunk009 ∈ csrChunks000 := by
  exact base7_csr_chunks030_member _ (List.mem_append_left _ (by decide))

theorem ciphertext_bridge_exact_lookup (output : Fin 2) (limb : Fin 6) :
    exactCsrAttempts[15653 + 6 * output.val + limb.val]? =
      some (ciphertextBridgeAttempt output.val limb.val) := by
  have member : ciphertextBridgeAttempt output.val limb.val ∈ exactCsrAttempts := by
    rw [← csr_chunks_equal_materialized_attempts]
    exact List.mem_flatten.mpr ⟨_,ciphertext_bridge_chunk_in_complete,
      ciphertext_bridge_chunk_member output limb⟩
  obtain ⟨position,found⟩ := List.getElem?_of_mem member
  have canonical := checkCsr_sound _ _ _ hgv8rp03_csr_check_passes position _ found
  have same : 15653 + 6 * output.val + limb.val = position := canonical.1.1
  rw [same]
  exact found

theorem ciphertext_bridge_source_field (statement : V8PublicStatement) (witness : V8Witness)
    (output : Fin 2) (limb : Fin 6) :
    ((fullTypedSourceCandidate statement witness).getD
      ((70 + 12 * output.val + limb.val) * 64) 0 : F) =
      ((encodePublicStatement statement).getD (32 + 6 * output.val + limb.val) 0 : F) := by
  have source := full_candidate_ciphertext_source_readback statement witness output limb ⟨0,by decide⟩
  rw [laneField_eq_packedWord _ _ _ (by unfold ciphertextSourceRow; omega)] at source
  simpa only [ciphertextSourceRow,encodedPublicField,V8Smz9SemanticDecoder.packedWord,
    Nat.add_zero,Nat.mul_comm] using source

theorem ciphertext_bridge_target (pub : Nat → F) (output : Fin 2) (limb : Fin 6) :
    actualCsrCoefficients pub (36 + 6 * output.val + limb.val) =
      pub (32 + 6 * output.val + limb.val) := by
  exact actual_csr_node_field_equation pub
    (show exactCsrExpressions[36 + 6 * output.val + limb.val]? =
      some (.publicWord (32 + 6 * output.val + limb.val)) by
      fin_cases output <;> fin_cases limb <;> decide)

theorem ciphertext_bridge_actual_residual_zero (statement : V8PublicStatement) (witness : V8Witness)
    (output : Fin 2) (limb : Fin 6) :
    actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
      (fullTypedSourceCandidate statement witness) (ciphertextBridgeAttempt output.val limb.val) = 0 := by
  simp only [ciphertextBridgeAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    (actual_csr_zero_one _).2,one_mul,add_zero,ciphertext_bridge_target,
    ciphertext_bridge_source_field,sub_self]

theorem ciphertext_bridge_exact_distinct_count :
    ((List.range 12).map fun i => 15653 + i).length = 12 ∧
      ((List.range 12).map fun i => 15653 + i).Nodup := by decide

theorem ciphertext_bridge_indexed_zero (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 12) :
    (exactCsrAttempts[15653 + index.val]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness)) = some 0 := by
  have split : 15653 + index.val = 15653 + 6 * (index.val / 6) + index.val % 6 := by omega
  rw [split,ciphertext_bridge_exact_lookup ⟨index.val / 6,by omega⟩ ⟨index.val % 6,by omega⟩,
    Option.map_some,ciphertext_bridge_actual_residual_zero]

end
end HegemonCrypto.SmallWood.V8Smz9SourceCipher12
