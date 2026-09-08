import HegemonCrypto.SmallWoodV8Smz9SourceNullifierWords
import HegemonCrypto.SmallWoodV8Smz9SourceAuthInitial128

namespace HegemonCrypto.SmallWood.V8Smz9SourceNullifierScalarRho
open Hegemon.Transaction
open Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (rawIndex hashInitialIndex hashFinalIndex inputNoteCall)
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceNullifierFrames
open HegemonCrypto.SmallWood.V8Smz9SourceNullifierWords
open HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames
open HegemonCrypto.SmallWood.V8Smz9SourceAuthInitial128
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9NullifierSource
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem full_candidate_nullifier_scalar_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (input : Fin 2) :
    actualCsrResidual pub (fullTypedSourceCandidate statement witness) (nullifierScalarAttempt input.val) = 0 := by
  simp only [nullifierScalarAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,(actual_csr_zero_one pub).1,
    (actual_csr_zero_one pub).2,actual_auth_initial_negative pub,one_mul,neg_one_mul,add_zero,sub_zero]
  rw [full_candidate_nullifier_initial_field statement witness valid input ⟨0,by decide⟩,
    if_pos (by decide),full_candidate_nullifier_scalar_word statement witness valid input]
  ring

theorem actual_nullifier_positive (pub : Nat → F) : actualCsrCoefficients pub 265 = 1 := by
  have node := actual_csr_node_field_equation pub
    (show exactCsrExpressions[265]? = some (.sub 0 158) by decide)
  simpa only [expressionField,(actual_csr_zero_one pub).1,actual_auth_initial_negative pub,zero_sub,neg_neg] using node

theorem full_candidate_note_rho_initial (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (limb : Fin 4) :
    ((fullTypedSourceCandidate statement witness).getD
      (hashInitialIndex (inputNoteCall input.val + (6 + limb.val) / 8) ((6 + limb.val) % 8)) 0 : F) =
      (if limb.val < 2 then 0 else ((fullTypedSourceCandidate statement witness).getD
        (hashFinalIndex (inputNoteCall input.val) (limb.val - 2)) 0 : F)) +
      ((HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule.sourceNoteWords
        (sourceNoteOpening witness input.val)).getD (6 + limb.val) 0 : F) := by
  have initial := full_candidate_note_initial_field statement witness valid
    ⟨input.val,by omega⟩ ⟨(6 + limb.val) / 8,by omega⟩ ⟨(6 + limb.val) % 8,by omega⟩
  have call : noteBridgeCall input.val = inputNoteCall input.val := by fin_cases input <;> rfl
  rw [call] at initial
  fin_cases limb <;> norm_num only at initial ⊢ <;> simpa using initial

theorem actual_nullifier_rho_residual (pub : Nat → F) (packed : List Nat) (input limb : Nat) :
    actualCsrResidual pub packed (nullifierRhoAttempt input limb) =
      (packed.getD (hashInitialIndex (nullifierCall input) (2 + limb)) 0 : F) -
      (packed.getD (hashInitialIndex (inputNoteCall input + (6 + limb) / 8) ((6 + limb) % 8)) 0 : F) +
      (if limb < 2 then 0 else (packed.getD (hashFinalIndex (inputNoteCall input) (limb - 2)) 0 : F)) := by
  by_cases first : limb < 2 <;>
    simp [nullifierRhoAttempt,attempt,actualCsrResidual,actualCsrTerms,first,
      (actual_csr_zero_one pub).1,(actual_csr_zero_one pub).2,actual_auth_initial_negative pub,
      actual_nullifier_positive pub,sub_eq_add_neg,add_assoc]

theorem full_candidate_nullifier_rho_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (input : Fin 2) (limb : Fin 4) :
    actualCsrResidual pub (fullTypedSourceCandidate statement witness) (nullifierRhoAttempt input.val limb.val) = 0 := by
  rw [actual_nullifier_rho_residual,full_candidate_note_rho_initial statement witness valid input limb,
    full_candidate_nullifier_initial_field statement witness valid input ⟨2 + limb.val,by omega⟩,
    if_pos (show 2 + limb.val < 6 by omega),actual_nullifier_rho_word statement witness valid input limb]
  ring

theorem nullifier_scalar_exact_lookup (input : Fin 2) :
    exactCsrAttempts[18300 + 16 * input.val]? = some (nullifierScalarAttempt input.val) :=
  exact_attempt_lookup _ (exact_nullifier_scalar_attempts input)

theorem nullifier_rho_exact_lookup (input : Fin 2) (limb : Fin 4) :
    exactCsrAttempts[18302 + 16 * input.val + limb.val]? = some (nullifierRhoAttempt input.val limb.val) :=
  exact_attempt_lookup _ (exact_nullifier_rho_attempts input limb)

end
end HegemonCrypto.SmallWood.V8Smz9SourceNullifierScalarRho
