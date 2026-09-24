import HegemonCrypto.SmallWoodV8Smz9SourceStableTimeResiduals
import HegemonCrypto.SmallWoodV8Smz9SourceStableRetirementProjections
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableRetirement4
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceStableTimeResiduals
open HegemonCrypto.SmallWood.V8Smz9SourceStableTimeArithmetic
open HegemonCrypto.SmallWood.V8Smz9SourceStableTimeParts
open HegemonCrypto.SmallWood.V8Smz9SourceStableRetirementProjections
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies (exact_attempt_lookup)
open HegemonCrypto.SmallWood.V8Smz9SemanticStableLifecycleEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableRetirementEndpoint
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem full_candidate_retirement_low_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 2) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (retirementLowAttempt index.val) = 0 := by
  have bounds := (exact_retirement_addition_attempts index.val index.isLt).2.2
  have x := source_time_parts_mod_div statement witness valid ⟨(retirementAddition index.val).x,bounds.1⟩
  have y := source_time_parts_mod_div statement witness valid ⟨(retirementAddition index.val).y,bounds.2.1⟩
  have z := source_time_parts_mod_div statement witness valid ⟨(retirementAddition index.val).z,bounds.2.2.1⟩
  rw [source_range_time_value statement witness ⟨_,bounds.1⟩] at x
  rw [source_range_time_value statement witness ⟨_,bounds.2.1⟩] at y
  rw [source_range_time_value statement witness ⟨_,bounds.2.2.1⟩] at z
  have b := full_candidate_multiplication_b_absolute statement witness (42329+2*index.val) (by omega) (by omega)
  rw [show 42329+2*index.val-42304=25+2*index.val by omega,
    retirement_source_b_low statement witness valid _ index] at b
  have carry := full_candidate_boolean_at statement witness ⟨(retirementAddition index.val).carry,bounds.2.2.2⟩
  rw [retirement_boolean_carry statement witness _ index] at carry
  rw [actual_retirement_low_residual]
  dsimp only
  rw [x.1,y.1,z.1,b,carry,source_low_residual_cast]
  norm_num only [limbBase,Nat.cast_pow,Nat.cast_ofNat]
  ring

theorem full_candidate_retirement_high_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 2) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (retirementHighAttempt index.val) = 0 := by
  have bounds := (exact_retirement_addition_attempts index.val index.isLt).2.2
  have x := source_time_parts_mod_div statement witness valid ⟨(retirementAddition index.val).x,bounds.1⟩
  have y := source_time_parts_mod_div statement witness valid ⟨(retirementAddition index.val).y,bounds.2.1⟩
  have z := source_time_parts_mod_div statement witness valid ⟨(retirementAddition index.val).z,bounds.2.2.1⟩
  rw [source_range_time_value statement witness ⟨_,bounds.1⟩] at x
  rw [source_range_time_value statement witness ⟨_,bounds.2.1⟩] at y
  rw [source_range_time_value statement witness ⟨_,bounds.2.2.1⟩] at z
  have b := full_candidate_multiplication_b_absolute statement witness (42330+2*index.val) (by omega) (by omega)
  rw [show 42330+2*index.val-42304=26+2*index.val by omega,
    retirement_source_b_high statement witness valid _ index] at b
  have carry := full_candidate_boolean_at statement witness ⟨(retirementAddition index.val).carry,bounds.2.2.2⟩
  rw [retirement_boolean_carry statement witness _ index] at carry
  have retiredBound : timeValue statement witness (sourceAux statement.stablecoin witness.stablecoin)
      (retirementAddition index.val).z < fieldModulus := by
    have source := lt_trans (valid_numeric_input_bounds statement witness valid).retiredAt (by decide : 2^63 < fieldModulus)
    fin_cases index <;> exact source
  rw [actual_retirement_high_residual]
  dsimp only
  rw [x.2,y.2,z.2,b,carry,source_high_residual_cast _ _ _ _ retiredBound]
  norm_num only [limbBase,Nat.cast_pow,Nat.cast_ofNat]
  ring

theorem full_candidate_actual_retirement4_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 2) (high : Bool) :
    (exactCsrAttempts[20421+2*index.val+(if high then 1 else 0)]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  cases high
  · have found := exact_attempt_lookup _ (exact_retirement_addition_attempts index.val index.isLt).1
    change exactCsrAttempts[20421+2*index.val]? = some (retirementLowAttempt index.val) at found
    simp only [Bool.false_eq_true,if_false,Nat.add_zero,found,Option.map_some,full_candidate_retirement_low_zero statement witness valid index]
  · have found := exact_attempt_lookup _ (exact_retirement_addition_attempts index.val index.isLt).2.1
    change exactCsrAttempts[20422+2*index.val]? = some (retirementHighAttempt index.val) at found
    change (exactCsrAttempts[20421+2*index.val+1]?).map _ = some 0
    rw [show 20421+2*index.val+1=20422+2*index.val by omega,found]
    simp only [Option.map_some,full_candidate_retirement_high_zero statement witness valid index]
end
end HegemonCrypto.SmallWood.V8Smz9SourceStableRetirement4
