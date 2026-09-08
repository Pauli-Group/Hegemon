import HegemonCrypto.SmallWoodV8Smz9SourceNoteFrames
import HegemonCrypto.SmallWoodV8Smz9SourceInactiveRaw92
import HegemonCrypto.SmallWoodV8Smz9SourceAuthInitial128

namespace HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames
open Hegemon.Transaction
open Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceAuthInitial128
open HegemonCrypto.SmallWood.V8Smz9SourceInactiveRaw92
open HegemonCrypto.SmallWood.V8Smz9SourceInactiveMerkleRight
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

def sourceNoteFlag (statement : V8PublicStatement) (note : Nat) : Nat :=
  if note < 2 then flagAt statement.inputFlags note else flagAt statement.outputFlags (note - 2)

theorem encoded_note_flag (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (note : Fin 4) :
    (encodePublicStatement statement).getD note.val 0 = sourceNoteFlag statement note.val := by
  fin_cases note
  · exact encoded_input_flag statement valid.1 (by decide : 0 < 2)
  · exact encoded_input_flag statement valid.1 (by decide : 1 < 2)
  · exact encoded_output_flag statement valid.1 (by decide : 0 < 2)
  · exact encoded_output_flag statement valid.1 (by decide : 1 < 2)

theorem source_note_flag_boolean (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (note : Fin 4) :
    sourceNoteFlag statement note.val = 0 ∨ sourceNoteFlag statement note.val = 1 := by
  by_cases input : note.val < 2
  · rw [sourceNoteFlag,if_pos input]
    exact boolean_getD statement.inputFlags valid.1.2.2.1 note.val
  · rw [sourceNoteFlag,if_neg input]
    exact boolean_getD statement.outputFlags valid.1.2.2.2.1 (note.val - 2)

theorem typed_inactive_note_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (note : Fin 4)
    (inactive : sourceNoteFlag statement note.val = 0) :
    ZeroNoteOpening (sourceNoteOpening witness note.val) := by
  by_cases input : note.val < 2
  · rw [sourceNoteOpening,if_pos input]
    rw [sourceNoteFlag,if_pos input] at inactive
    exact (typed_inactive_input_zero statement witness valid ⟨note.val,input⟩ inactive).2.2.2.1
  · rw [sourceNoteOpening,if_neg input]
    rw [sourceNoteFlag,if_neg input] at inactive
    exact (typed_inactive_output_zero statement witness valid ⟨note.val - 2,by omega⟩ inactive).2.1

theorem zero_note_source_words (note : V8NoteOpening) (zero : ZeroNoteOpening note) :
    sourceNoteWords note = List.replicate 18 0 := by
  rcases zero with ⟨value,asset,_,recipient,_,key,_,rho,_,randomness⟩
  have fixedZero (words : List Nat) (allZero : ZeroWords words) : fixedWords 4 words = List.replicate 4 0 := by
    calc
      fixedWords 4 words = (List.range 4).map (fun _ => 0) :=
        List.map_congr_left (by intro i _; exact zero_words_getD words allZero i)
      _ = List.replicate 4 0 := rfl
  rw [sourceNoteWords,fixedZero _ recipient,fixedZero _ rho,fixedZero _ randomness,fixedZero _ key,value,asset]
  rfl

theorem typed_inactive_note_word_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (note : Fin 4) (word : Nat)
    (inactive : sourceNoteFlag statement note.val = 0) :
    (sourceNoteWords (sourceNoteOpening witness note.val)).getD word 0 = 0 := by
  rw [zero_note_source_words _ (typed_inactive_note_zero statement witness valid note inactive)]
  simp only [List.getD_eq_getElem?_getD,List.getElem?_replicate]
  split_ifs <;> rfl

theorem actual_inactive_note_coefficients (pub : Nat → F) (note : Fin 4) :
    actualCsrCoefficients pub (124 + note.val) = 1 - pub note.val ∧
      actualCsrCoefficients pub (inactiveNegativeRoot note.val) = -(1 - pub note.val) := by
  have nodes := exact_inactive_coefficient_nodes note.val note.isLt
  have p := actual_csr_node_field_equation pub nodes.1
  have g := actual_csr_node_field_equation pub nodes.2.1
  have n := actual_csr_node_field_equation pub nodes.2.2
  have gate : actualCsrCoefficients pub (124 + note.val) = 1 - pub note.val := by
    simpa only [expressionField,(actual_csr_zero_one pub).2,p] using g
  exact ⟨gate,by simpa only [expressionField,gate,actual_auth_initial_negative pub,mul_neg_one] using n⟩

theorem actual_inactive_note_residual (pub : Nat → F) (packed : List Nat) (note : Fin 4) (word : Nat) :
    actualCsrResidual pub packed (inactiveNoteExpectedAttempt note.val word) =
      (1 - pub note.val) *
        ((packed.getD (hashInitialIndex (noteBridgeCall note.val + word / 8) (word % 8)) 0 : F) -
         (if word / 8 = 0 then 0 else
          (packed.getD (hashFinalIndex (noteBridgeCall note.val + word / 8 - 1) (word % 8)) 0 : F))) := by
  have coeff := actual_inactive_note_coefficients pub note
  by_cases first : word / 8 = 0 <;>
    simp [inactiveNoteExpectedAttempt,actualCsrResidual,actualCsrTerms,attempt,first,
      coeff.1,coeff.2,(actual_csr_zero_one pub).1]
  ring

theorem full_candidate_inactive_note_residual_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (note : Fin 4) (word : Fin 18) :
    actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
      (fullTypedSourceCandidate statement witness) (inactiveNoteExpectedAttempt note.val word.val) = 0 := by
  rw [actual_inactive_note_residual,encoded_note_flag statement witness valid note,
    full_candidate_note_initial_field statement witness valid note
      ⟨word.val / 8,by omega⟩ ⟨word.val % 8,by omega⟩]
  have rate : word.val % 8 < 8 ∧ word.val / 8 * 8 + word.val % 8 < 18 := by omega
  have index : word.val / 8 * 8 + word.val % 8 = word.val := by omega
  rw [if_pos rate,index]
  rcases source_note_flag_boolean statement witness valid note with inactive | active
  · rw [typed_inactive_note_word_zero statement witness valid note word.val inactive]
    simp only [Nat.cast_zero,add_zero,sub_self,mul_zero]
  · rw [active]
    simp only [Nat.cast_one,sub_self,zero_mul]

theorem inactive_note_exact_lookup (note : Fin 4) (word : Fin 18) :
    exactCsrAttempts[inactiveNoteAttemptIndex note.val + word.val]? =
      some (inactiveNoteExpectedAttempt note.val word.val) :=
  exact_attempt_lookup _ (exact_inactive_note_attempts note.val note.isLt word.val word.isLt)

def inactiveNote72Index (index : Nat) : Nat := inactiveNoteAttemptIndex (index / 18) + index % 18

theorem inactive_note72_distinct_count :
    ((List.range 72).map inactiveNote72Index).length = 72 ∧
      ((List.range 72).map inactiveNote72Index).Nodup := by decide

theorem full_candidate_actual_inactive_note72_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 72) :
    (exactCsrAttempts[inactiveNote72Index index.val]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness)) = some 0 := by
  rw [inactiveNote72Index,inactive_note_exact_lookup ⟨index.val / 18,by omega⟩ ⟨index.val % 18,by omega⟩,
    Option.map_some,full_candidate_inactive_note_residual_zero statement witness valid]

end
end HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames
