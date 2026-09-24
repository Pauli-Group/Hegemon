import HegemonCrypto.SmallWoodV8Smz9SourceNullifierWords
import HegemonCrypto.SmallWoodV8Smz9SourceNullifierScalarRho
import HegemonCrypto.SmallWoodV8Smz9SourcePositionReconstruction

namespace HegemonCrypto.SmallWood.V8Smz9SourceNullifierPosition
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (rawIndex inputDirectionRow)
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceNullifierFrames
open HegemonCrypto.SmallWood.V8Smz9SourceNullifierWords
open HegemonCrypto.SmallWood.V8Smz9SourceNullifierScalarRho
open HegemonCrypto.SmallWood.V8Smz9SourceAuthInitial128
open HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr
open HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9NullifierSource
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem full_candidate_input_position_bit (statement : V8PublicStatement) (witness : V8Witness)
    (input : Fin 2) (bit : Fin 32) :
    ((fullTypedSourceCandidate statement witness).getD (rawIndex (inputDirectionRow input.val bit.val)) 0 : F) =
      (positionBit (witness.inputs.getD input.val default).position bit.val : F) := by
  have row : inputDirectionRow input.val bit.val = 34 * input.val + (2 + bit.val) := by
    unfold inputDirectionRow
    omega
  rw [row,full_candidate_all_raw_word statement witness ⟨_,by omega⟩,constructedRawWord,
    if_pos (show 34 * input.val + (2 + bit.val) < 92 by omega),
    source_input_word statement witness input.val (2 + bit.val) input.isLt (by omega)]
  simp only [inputWord,if_neg (by omega : ¬2 + bit.val = 0),if_neg (by omega : ¬2 + bit.val = 1),Nat.add_sub_cancel_left]

theorem actual_position_negative_coefficient (pub : Nat → F) (bit : Fin 32) :
    actualCsrCoefficients pub (positionNegativeRoot bit.val) = -((2 ^ bit.val : Nat) : F) := by
  have nodes := exact_position_coefficient_nodes bit
  have positive := actual_csr_node_field_equation pub nodes.1
  have negative := actual_csr_node_field_equation pub nodes.2
  simpa only [expressionField,(actual_csr_zero_one pub).1,positive,zero_sub] using negative

theorem full_candidate_position_terms (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (input : Fin 2) :
    actualCsrTerms pub (fullTypedSourceCandidate statement witness) (nullifierPositionTerms input.val) =
      -((witness.inputs.getD input.val default).position : F) := by
  have mapped : (List.range 32).map (fun bit =>
      actualCsrCoefficients pub (positionNegativeRoot bit) *
        ((fullTypedSourceCandidate statement witness).getD (rawIndex (inputDirectionRow input.val bit)) 0 : F)) =
      ((List.range 32).map (fun bit => 2 ^ bit * positionBit (witness.inputs.getD input.val default).position bit)).map
        (fun (value : Nat) => -(value : F)) := by
    rw [List.map_map]
    apply List.map_congr_left
    intro bit member
    rw [actual_position_negative_coefficient pub ⟨bit,List.mem_range.mp member⟩,
      full_candidate_input_position_bit statement witness input ⟨bit,List.mem_range.mp member⟩]
    simp only [Function.comp_apply,Nat.cast_mul,neg_mul]
  unfold actualCsrTerms nullifierPositionTerms
  rw [List.map_map]
  change ((List.range 32).map (fun bit =>
    actualCsrCoefficients pub (positionNegativeRoot bit) *
      ((fullTypedSourceCandidate statement witness).getD (rawIndex (inputDirectionRow input.val bit)) 0 : F))).sum = _
  rw [mapped,sum_neg_cast]
  rw [HegemonCrypto.SmallWood.V8Smz9SourcePositionReconstruction.position_bits32_exact _
    (typed_input_position_bounded statement witness valid input)]

theorem full_candidate_nullifier_position_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (input : Fin 2) :
    actualCsrResidual pub (fullTypedSourceCandidate statement witness) (nullifierPositionAttempt input.val) = 0 := by
  simp only [nullifierPositionAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.sum_cons,(actual_csr_zero_one pub).1,(actual_csr_zero_one pub).2,one_mul,sub_zero]
  change ((fullTypedSourceCandidate statement witness).getD
    (Poseidon2V8DecoderRefinement.hashInitialIndex (nullifierCall input.val) 1) 0 : F) +
    actualCsrTerms pub (fullTypedSourceCandidate statement witness) (nullifierPositionTerms input.val) = 0
  rw [full_candidate_position_terms statement witness valid pub input,
    full_candidate_nullifier_initial_field statement witness valid input ⟨1,by decide⟩,
    if_pos (by decide),actual_nullifier_position_word statement witness valid input]
  ring

theorem nullifier_position_exact_lookup (input : Fin 2) :
    exactCsrAttempts[18301 + 16 * input.val]? = some (nullifierPositionAttempt input.val) :=
  exact_attempt_lookup _ (exact_nullifier_position_attempts input)

end
end HegemonCrypto.SmallWood.V8Smz9SourceNullifierPosition
